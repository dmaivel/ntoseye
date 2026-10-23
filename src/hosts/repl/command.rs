use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::OnceLock;

use linkme::distributed_slice;

use crate::base::error::Result;
use crate::hosts::repl::usage::ArgGrammar;
use crate::hosts::repl::{CompletionStrategy, Flow, ReplState, error};
use crate::hosts::ui;
use crate::session::effects::{Effects, Refusal};

#[distributed_slice]
pub static COMMANDS: [CommandSpec];

/// One command: its names and help (the REPL's `help`, the docs' command
/// reference), how its arguments complete, what it needs and changes
/// ([`Effects`], which [`crate::session::Session::admit`] enforces), and its
/// handler. Every `#[command]` registers one in [`COMMANDS`].
pub struct CommandSpec {
    pub names: &'static [&'static str],
    /// The `help` listing's and the command reference's group.
    pub category: &'static str,
    pub kind: CommandKind,
    /// Generated from `args`: a line per form of the command, each
    /// starting with its canonical name (see [`crate::hosts::repl::usage`]).
    pub usage: &'static str,
    pub summary: &'static str,
    pub details: Option<&'static str>,
    /// Generated from `args`: how each word of the line completes.
    pub completion: CompletionSpec,
    /// The arguments the line gives, in order, with their grammar.
    pub args: &'static [ArgGrammar],
    pub effects: Effects,
    pub style: CommandStyle,
    pub flow: Flow,
    pub handler: CommandHandler,
}

/// What a `#[command]` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandKind {
    /// Reads state and returns a record.
    Query,
    /// Changes guest, debugger or symbol state and returns what changed.
    Action,
    /// Resumes or steps the target.
    Run,
    /// Acts on the REPL itself (aliases, scripting, output); no SDK form.
    Host,
}

/// How a `#[command]`'s result reads in the REPL. `O` is the command's
/// render options, its `#[arg(render)]` arguments (one value, or a tuple
/// in order): the WinDbg flags that only choose what the text shows, which
/// the record never depends on. The text goes through `outln!`, which the
/// host captures; the REPL state is there for what only the REPL keeps
/// (completion caches, the inspection selection) and for text that
/// composes further reads, such as a thread's stack.
pub trait Render<O = ()> {
    fn render(&self, repl: &mut ReplState<'_>, options: O);
}

/// An action that printed what it did as it went.
impl Render for () {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {}
}

/// A result that is one line of text (a path the command wrote).
impl Render for String {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!("{self}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStyle {
    StructuredArgs,
    RawTail,
    ExpressionTail,
}

/// How a command's words complete: the `n`th word by `words[n]`, and every
/// word after them by `rest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionSpec {
    pub words: &'static [CompletionStrategy],
    pub rest: CompletionStrategy,
}

impl CompletionSpec {
    pub fn strategy_for_arg(self, index: usize) -> CompletionStrategy {
        self.words.get(index).copied().unwrap_or(self.rest)
    }
}

#[derive(Clone, Copy)]
pub enum CommandHandler {
    Args(fn(&mut ReplState<'_>, CommandInvocation<'_>) -> Result<()>),
    /// A command that dispatches other commands (`.foreach`, `!list -x`) and
    /// passes on how they ended, so a refusal inside it abandons the rest of
    /// the line and reaches the host as one typed directly would.
    ArgsFlow(fn(&mut ReplState<'_>, CommandInvocation<'_>) -> Result<Flow>),
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
}

pub struct CommandRegistry {
    by_name: HashMap<&'static str, &'static CommandSpec>,
}

impl CommandRegistry {
    pub fn get(&self, name: &str) -> Option<&'static CommandSpec> {
        self.by_name.get(name).copied()
    }

    /// Whether some command's name starts with `prefix`.
    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.by_name.keys().any(|name| name.starts_with(prefix))
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

/// `reason`, then command `name`'s generated usage, its forms on one line
/// joined by ` | `: what a command reports for a line it cannot read, so no
/// message spells out a usage by hand.
pub fn usage_error(name: &str, reason: impl std::fmt::Display) -> String {
    match command_registry().get(name) {
        Some(spec) => format!("{reason}; usage: {}", spec.usage.replace('\n', " | ")),
        None => reason.to_string(),
    }
}

/// A command's summary, usage and details as text.
pub fn spec_help(spec: &CommandSpec) -> String {
    // A form per line, under the first.
    let usage = spec.usage.replace('\n', "\n        ");
    let mut help = format!("{}\n(usage: {usage})", spec.summary);
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
    crate::base::diagnostics::note_error();
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

/// Report why [`crate::session::Session::admit`] refused a command run as
/// `typed`, worded as the REPL always has.
pub fn report_refusal(typed: &str, refusal: Refusal) {
    match refusal {
        Refusal::KernelRequired(error) => error!("{typed}: {error}"),
        Refusal::Running {
            unreachable,
            or_parked_thread,
        } => {
            let or_thread = if or_parked_thread {
                ", or a thread selected with `.thread`"
            } else {
                ""
            };
            match unreachable {
                Some(reason) => error!("this command needs a halted target{or_thread}; {reason}"),
                None => error!("VM is running; this command needs a halted target{or_thread}"),
            }
        }
        // `break` on a halted target has nothing to do, which is what it
        // was asked for: `break; bp ...; g` holds whichever state it starts
        // in.
        Refusal::AlreadyHalted => {
            outln!("{}", ui::muted("the target is already halted"))
        }
        Refusal::NoExecutionControl { backend } => {
            error!("the {backend} backend cannot run or step the target")
        }
        Refusal::StaticDump => error!("{typed} is not applicable to a static crash dump"),
        Refusal::Unsupported {
            capability,
            backend,
        } => error!(
            "{typed} needs {} support, which the {backend} backend lacks",
            capability.label()
        ),
        Refusal::Vtl1(refusal) => error!("{}", refusal.message(typed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_errors_quote_the_generated_usage_on_one_line() {
        assert_eq!(
            usage_error("!reg", "!reg: unknown subcommand x"),
            "!reg: unknown subcommand x; usage: !reg hivelist | \
             !reg querykey|q <path> [-v <value>] | !reg keyinfo <hive> <knode> | \
             !reg cellindex <hive> <cell>"
        );
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

    /// Every argument that names a value (a `<placeholder>`, or a typed
    /// argument's `{}`) has a completion at its words' position, or takes
    /// the rest of the line; and no argument that takes words follows one
    /// that takes the rest of the line, where it would have no position.
    #[test]
    fn completion_covers_every_argument() {
        let mut uncovered = Vec::new();
        for spec in COMMANDS {
            let name = spec.names[0];
            let mut at = 0;
            let mut rest = None;
            for arg in spec.args {
                let grammar = arg.grammar;
                let names_value = grammar.usage.contains('<') || grammar.usage.contains("{}");
                if names_value && rest.is_some() {
                    uncovered.push(format!(
                        "{name}: `{}` follows an argument that takes the rest of the line",
                        arg.name
                    ));
                }
                if names_value && grammar.words.is_empty() && grammar.rest.is_none() {
                    uncovered.push(format!(
                        "{name}: `{}` ({}) has no completion",
                        arg.name, grammar.usage
                    ));
                }
                if rest.is_none() {
                    assert_eq!(
                        spec.completion.words.get(at..at + grammar.words.len()),
                        Some(grammar.words),
                        "{name}: `{}`'s words complete at their position",
                        arg.name
                    );
                    at += grammar.words.len();
                    rest = grammar.rest;
                }
            }
            assert_eq!(spec.completion.words.len(), at, "{name}");
            assert_eq!(
                spec.completion.rest,
                rest.unwrap_or(CompletionStrategy::None),
                "{name}"
            );
        }
        assert!(uncovered.is_empty(), "{}", uncovered.join("\n"));
    }
}
