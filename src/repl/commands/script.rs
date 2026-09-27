//! Debugger command programs: the control-flow tokens (`.if`, `.while`,
//! `.for`, `.do`, `.break`, `.continue`, `.block`), `j`, script files (`$<`,
//! `$$>a<`...), comments, `.sleep`, and the `$t0`-`$t19` slots `r` assigns.
//! As with `.foreach`, every command they run goes through `dispatch_line`,
//! so its output reaches whichever host is capturing, and a refused command
//! abandons the rest of the line.

use std::borrow::Cow;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::diagnostics::print_warning;
use crate::error::Result;
use crate::expr::{Expr, NumberRadix};
use crate::target::{Target, UserVar};
use crate::ui;

use crate::repl::commands::foreach::{substitute, take_block};
use crate::repl::*;

/// How often `.sleep` looks for Ctrl+C.
const SLEEP_POLL: Duration = Duration::from_millis(50);

repl_command! {
    cmd_if -> Flow;
    names: [".if"],
    usage: ".if (Condition) { Commands } [.elsif (Condition) { Commands }]... [.else { Commands }]",
    summary: "Run a block of commands if a condition holds, as C's if.",
    details: "Each Condition is an expression; nonzero is true. The block of the first condition that holds runs, else the .else block if there is one. The parts may be separated by spaces, line breaks, or the `;` a script run with `$$><` puts at each line break, and commands after the statement run once it ends: `.if (@rcx == 0) { .echo null } .else { dq @rcx L1 }; k`.",
    style: RawTail,
}

repl_command! {
    cmd_orphan_else -> Flow;
    names: [".elsif"],
    usage: ".if (Condition) { Commands } .elsif (Condition) { Commands }",
    summary: "Add a condition to an .if statement.",
    details: "Only valid right after an .if or .elsif block; see .if.",
    style: RawTail,
}

repl_command! {
    cmd_orphan_else -> Flow;
    names: [".else"],
    usage: ".if (Condition) { Commands } .else { Commands }",
    summary: "Run a block when no condition of an .if statement holds.",
    details: "Only valid right after an .if or .elsif block; see .if.",
    style: RawTail,
}

repl_command! {
    cmd_while -> Flow;
    names: [".while"],
    usage: ".while (Condition) { Commands }",
    summary: "Run a block of commands while a condition holds.",
    details: "Condition is an expression, evaluated before each pass; nonzero is true. .break leaves the loop and .continue starts the next pass. Ctrl+C, or a remote call's timeout or cancellation, stops the loop between passes. A command the session refuses ends the loop and the rest of the command line.",
    style: RawTail,
}

repl_command! {
    cmd_for -> Flow;
    names: [".for"],
    usage: ".for (InitialCommand ; Condition ; IncrementCommand) { Commands }",
    summary: "Run a block of commands in a loop, as C's for.",
    details: "InitialCommand runs once; then, while the expression Condition is nonzero, the block runs followed by IncrementCommand. The two commands are typically pseudo-register assignments: `.for (r $t0 = 0; @$t0 < 4; r $t0 = @$t0 + 1) { ? @$t0 }`. .break leaves the loop and .continue skips to IncrementCommand. Ctrl+C, or a remote call's timeout or cancellation, stops the loop between passes.",
    style: RawTail,
}

repl_command! {
    cmd_do -> Flow;
    names: [".do"],
    usage: ".do { Commands } (Condition)",
    summary: "Run a block of commands, then again while a condition holds.",
    details: "Condition is an expression, evaluated after each pass; nonzero is true. .break leaves the loop and .continue skips to the condition. Ctrl+C, or a remote call's timeout or cancellation, stops the loop between passes.",
    style: RawTail,
}

repl_command! {
    cmd_break -> Flow;
    names: [".break"],
    usage: ".break",
    summary: "Leave the innermost .for, .while, or .do loop.",
    details: "As in WinDbg, .foreach and !for_each_* loops are not left by .break; usually it sits in an .if block: `.while (1) { r $t0 = @$t0 + 1; .if (@$t0 > 5) { .break } }`.",
}

repl_command! {
    cmd_continue -> Flow;
    names: [".continue"],
    usage: ".continue",
    summary: "Start the next pass of the innermost .for, .while, or .do loop.",
}

repl_command! {
    cmd_block -> Flow;
    names: [".block"],
    usage: ".block { Commands }",
    summary: "Run a block of commands.",
    details: "WinDbg uses a block to re-evaluate its `${alias}` aliases; ntoseye expands aliases as each command runs, so a block only groups commands.",
    style: RawTail,
}

repl_command! {
    cmd_j -> Flow;
    names: ["j"],
    usage: "j Expression Command1 ; Command2 | j Expression 'Commands1' ; 'Commands2'",
    summary: "Run one command or another depending on an expression.",
    details: "Command1 runs if Expression is nonzero, else Command2. Single quotes hold several commands separated by `;`, and either may be empty (`''`, or nothing before the `;`). j takes the rest of the line, so text after Command2 is ignored. In a breakpoint action, `gc` in either branch resumes: `bp nt!NtClose \"j (@rcx == 0) '.echo null handle' ; 'gc'\"`.",
    style: RawTail,
}

repl_command! {
    names: ["$<", "$><", "$$<", "$$><", "$$>a<"],
    usage: "$<Filename | $><Filename | $$<Filename | $$><Filename | $$>a<Filename [arg1 arg2 ...]",
    summary: "Run the commands in a script file on the machine ntoseye runs on.",
    details: "`$<` and `$$<` run the file one line at a time. `$><`, `$$><`, and `$$>a<` join its lines with `;` into one command block, which a program whose .if or .while blocks span lines needs. `$<` and `$><` take the rest of the line as the file name, `;` included; the `$$` forms end at `;`, so other commands may follow. `$$>a<` takes a quoted file name when it has spaces, replaces `${$arg1}`...`${$argN}` in the file with its arguments as written, leaves an argument not given as written, and replaces `${/d:$argN}` with 1 when argument N was given, else 0. `$$>a<` shows only the commands' output; the others echo each command first. Scripts may run scripts, 16 deep. Ctrl+C stops a script between commands.",
    flow: Continue,
}

repl_command! {
    names: ["$$", "*"],
    usage: "$$ Text | * Text",
    summary: "A comment: `$$` up to the next `;`, `*` to the end of the line.",
    flow: Continue,
}

repl_command! {
    cmd_sleep;
    names: [".sleep"],
    usage: ".sleep Milliseconds",
    summary: "Pause the debugger for a number of milliseconds.",
    details: "Milliseconds is an expression in the current radix (`.sleep 0n500`). Ctrl+C, or a remote call's timeout or cancellation, ends the pause early. The target is left as it is: a running target runs on.",
    completion: Expression,
}

/// The inside of the `( ... )` at the start of `text`, and what follows it.
/// Parentheses inside quoted strings do not count.
fn take_parens(text: &str) -> std::result::Result<(&str, &str), String> {
    if !text.starts_with('(') {
        return Err("expected '('".to_string());
    }
    let mut depth = 0usize;
    let scan = scan_unquoted(text, |_, ch| {
        match ch {
            '(' => depth += 1,
            ')' => {
                // The opening parenthesis counted first, so this never underflows.
                depth -= 1;
                return depth == 0;
            }
            _ => {}
        }
        false
    });
    match scan {
        Unquoted::Stopped(close) => Ok((&text[1..close], &text[close + 1..])),
        Unquoted::End | Unquoted::OpenQuote(_) => Err("unbalanced '('".to_string()),
    }
}

/// `text` past what may separate the parts of a statement: whitespace, and
/// the `;` a joined script puts at each line break.
fn skip_separators(text: &str) -> &str {
    text.trim_start_matches(|ch: char| ch.is_whitespace() || ch == ';')
}

/// What follows `token` when `text` opens with it as a whole word.
fn strip_token<'a>(text: &'a str, token: &str) -> Option<&'a str> {
    text.strip_prefix(token)
        .filter(|rest| !rest.starts_with(|ch: char| ch.is_alphanumeric() || ch == '_'))
}

fn condition_block(text: &str) -> std::result::Result<(&str, &str, &str), String> {
    let (condition, rest) = take_parens(text.trim_start())?;
    let (body, rest) = take_block(skip_separators(rest))?;
    Ok((condition.trim(), body, rest))
}

/// An `.if` statement: each `.if`/`.elsif` condition with its block, the
/// `.else` block, and the rest of the line after the statement.
#[derive(Debug, PartialEq, Eq)]
struct IfStatement<'a> {
    arms: Vec<(&'a str, &'a str)>,
    otherwise: Option<&'a str>,
    rest: &'a str,
}

fn parse_if(tail: &str) -> std::result::Result<IfStatement<'_>, String> {
    let (condition, body, mut rest) = condition_block(tail)?;
    let mut arms = vec![(condition, body)];
    let mut otherwise = None;
    loop {
        let next = skip_separators(rest);
        if let Some(after) = strip_token(next, ".elsif") {
            let (condition, body, after) =
                condition_block(after).map_err(|error| format!(".elsif: {error}"))?;
            arms.push((condition, body));
            rest = after;
        } else if let Some(after) = strip_token(next, ".else") {
            let (body, after) =
                take_block(skip_separators(after)).map_err(|error| format!(".else: {error}"))?;
            otherwise = Some(body);
            rest = after;
            break;
        } else {
            break;
        }
    }
    Ok(IfStatement {
        arms,
        otherwise,
        rest,
    })
}

/// A `.while`, `.for`, or `.do` loop.
#[derive(Debug, PartialEq, Eq)]
struct LoopStatement<'a> {
    init: Option<&'a str>,
    condition: &'a str,
    step: Option<&'a str>,
    body: &'a str,
    /// Whether the condition is tested before each pass (`.while`, `.for`)
    /// rather than after it (`.do`).
    test_first: bool,
    rest: &'a str,
}

fn parse_while(tail: &str) -> std::result::Result<LoopStatement<'_>, String> {
    let (condition, body, rest) = condition_block(tail)?;
    Ok(LoopStatement {
        init: None,
        condition,
        step: None,
        body,
        test_first: true,
        rest,
    })
}

fn parse_for(tail: &str) -> std::result::Result<LoopStatement<'_>, String> {
    let (header, rest) = take_parens(tail.trim_start())?;
    let mut parts = Vec::with_capacity(3);
    let mut start = 0;
    let mut depth = 0usize;
    let scan = scan_unquoted(header, |offset, ch| {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                parts.push(header[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
        false
    });
    if let Unquoted::OpenQuote(_) = scan {
        return Err("unterminated quoted string".to_string());
    }
    parts.push(header[start..].trim());
    let [init, condition, step] = parts[..] else {
        return Err("expected (InitialCommand ; Condition ; IncrementCommand)".to_string());
    };
    if condition.is_empty() {
        return Err("missing Condition".to_string());
    }
    let (body, rest) = take_block(skip_separators(rest))?;
    Ok(LoopStatement {
        init: Some(init),
        condition,
        step: Some(step),
        body,
        test_first: true,
        rest,
    })
}

fn parse_do(tail: &str) -> std::result::Result<LoopStatement<'_>, String> {
    let (body, rest) = take_block(tail.trim_start())?;
    let (condition, rest) = take_parens(skip_separators(rest))?;
    Ok(LoopStatement {
        init: None,
        condition: condition.trim(),
        step: None,
        body,
        test_first: false,
        rest,
    })
}

/// A parsed `j`: its condition, the two command strings, and whatever
/// followed Command2 (which j ignores).
#[derive(Debug, PartialEq, Eq)]
struct JCommand<'a> {
    condition: &'a str,
    then: Cow<'a, str>,
    otherwise: Cow<'a, str>,
    ignored: &'a str,
}

/// Split j's expression from its commands, which start at the first quote
/// or `;` outside parentheses at the latest. An unquoted Command1 starts
/// earlier, at the first word naming a command (`is_command`) after words
/// that parse as an expression: `j @rcx == 0 r rax ; k`.
fn split_j_condition(
    tail: &str,
    radix: NumberRadix,
    is_command: impl Fn(&str) -> bool,
) -> std::result::Result<(&str, &str), String> {
    let mut depth = 0usize;
    let end = tail
        .char_indices()
        .find(|&(_, ch)| {
            match ch {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                '\'' | '"' | ';' if depth == 0 => return true,
                _ => {}
            }
            false
        })
        .map_or(tail.len(), |(offset, _)| offset);
    let candidate = &tail[..end];
    let parses = |text: &str| Expr::parse_with_radix(text, radix).is_ok();
    let word_starts = candidate.char_indices().filter(|&(offset, ch)| {
        offset > 0 && !ch.is_whitespace() && candidate[..offset].ends_with(char::is_whitespace)
    });
    for (offset, _) in word_starts {
        let word = candidate[offset..]
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if is_command(word) && parses(&candidate[..offset]) {
            return Ok((&candidate[..offset], &tail[offset..]));
        }
    }
    if parses(candidate) {
        return Ok((candidate, &tail[end..]));
    }
    Err(format!(
        "expected an expression, found '{}'",
        candidate.trim()
    ))
}

/// One of j's command strings: single-quoted (unescaped as quoted arguments
/// are), or one command up to the next `;`.
fn take_j_command(text: &str) -> std::result::Result<(Cow<'_, str>, &str), String> {
    let text = text.trim_start();
    if text.starts_with('\'') {
        let (commands, rest) =
            take_quoted(text).ok_or_else(|| "unterminated quoted command string".to_string())?;
        return Ok((Cow::Owned(commands), rest));
    }
    let end = match scan_unquoted(text, |_, ch| ch == ';') {
        Unquoted::Stopped(offset) => offset,
        Unquoted::End => text.len(),
        Unquoted::OpenQuote(_) => return Err("unterminated quoted argument".to_string()),
    };
    Ok((Cow::Borrowed(text[..end].trim()), &text[end..]))
}

fn parse_j(
    tail: &str,
    radix: NumberRadix,
    is_command: impl Fn(&str) -> bool,
) -> std::result::Result<JCommand<'_>, String> {
    let (condition, rest) = split_j_condition(tail.trim(), radix, is_command)?;
    let (then, rest) = take_j_command(rest)?;
    let rest = rest.trim_start();
    let (otherwise, ignored) = if rest.is_empty() {
        (Cow::Borrowed(""), rest)
    } else {
        let rest = rest
            .strip_prefix(';')
            .ok_or_else(|| format!("expected ';' after Command1, found '{rest}'"))?;
        let (otherwise, ignored) = take_j_command(rest)?;
        let ignored = ignored.trim_start();
        (
            otherwise,
            ignored.strip_prefix(';').unwrap_or(ignored).trim(),
        )
    };
    Ok(JCommand {
        condition: condition.trim(),
        then,
        otherwise,
        ignored,
    })
}

/// The `$$>a<` value of an alias in a script: `$argN` for a given argument
/// N, and `/d:$argN` for whether it was given.
fn script_argument(args: &[Cow<'_, str>], name: &str) -> Option<String> {
    let index = |name: &str| {
        name.strip_prefix("$arg")
            .filter(|digits| !digits.starts_with('0'))
            .and_then(|digits| digits.parse::<usize>().ok())
    };
    if let Some(defined) = name.strip_prefix("/d:") {
        return index(defined).map(|index| u8::from(index <= args.len()).to_string());
    }
    let index = index(name)?;
    args.get(index.checked_sub(1)?).map(|arg| arg.to_string())
}

/// `text` without the quotes around it when it is one quoted string.
fn unquote_whole(text: &str) -> Cow<'_, str> {
    match take_quoted(text) {
        Some((inner, rest)) if rest.trim().is_empty() => Cow::Owned(inner),
        _ => Cow::Borrowed(text),
    }
}

/// `$tN`/`@$tN`, then optionally `= expression`: the slot's variable name
/// (`t0`) and the expression. `None` for any other `r` operand.
pub fn pseudo_register_operand(tail: &str) -> Option<(String, Option<&str>)> {
    let tail = tail.trim();
    let (name, value) = match tail.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim())),
        None => (tail, None),
    };
    let slot = name
        .strip_prefix('@')
        .unwrap_or(name)
        .strip_prefix('$')?
        .to_ascii_lowercase();
    Target::user_pseudo_register_slot(&slot)?;
    Some((slot, value))
}

enum LoopStep {
    Next,
    Leave,
    Return(Flow),
}

/// Where a loop goes after one of its commands ended with `flow`.
fn loop_step(name: &str, flow: Flow) -> LoopStep {
    match flow {
        Flow::Continue | Flow::Jump(Jump::Continue) => LoopStep::Next,
        Flow::Jump(Jump::Break) => LoopStep::Leave,
        Flow::Quit => {
            error!("{name}: quit is ignored inside a command loop");
            LoopStep::Return(Flow::Denied)
        }
        flow => LoopStep::Return(flow),
    }
}

impl ReplState<'_> {
    /// Whether `condition` holds; `None` (reported) when it cannot be
    /// evaluated.
    fn condition_holds(&self, name: &str, condition: &str) -> Option<bool> {
        match Expr::eval_with_radix(condition, &self.ctx.target, self.radix) {
            Ok(value) => Some(value.0 != 0),
            Err(error) => {
                error!("{name}: condition '{condition}': {error}");
                None
            }
        }
    }

    /// Run a statement's block, one level deeper in the command-loop nesting
    /// so a statement that runs itself (through an alias or a script) ends
    /// with an error instead of the stack.
    fn run_block(&mut self, name: &str, body: &str) -> Result<Flow> {
        self.in_command_loop(name, |state| state.dispatch_line(body))
    }

    /// The commands after a statement on its line, once it ended normally.
    fn then_rest(&mut self, flow: Flow, rest: &str) -> Result<Flow> {
        match flow {
            Flow::Continue if !rest.trim().is_empty() => self.dispatch_line(rest),
            flow => Ok(flow),
        }
    }

    /// Report a statement that does not parse. The rest of its line cannot
    /// be told apart from it, so the line is abandoned.
    fn malformed(name: &str, error: String) -> Result<Flow> {
        error!("{name}: {error}");
        Ok(Flow::Denied)
    }

    fn cmd_if(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        let statement = match parse_if(invocation.raw_tail) {
            Ok(statement) => statement,
            Err(error) => return Self::malformed(".if", error),
        };
        let mut chosen = statement.otherwise;
        for &(condition, body) in &statement.arms {
            match self.condition_holds(".if", condition) {
                Some(true) => {
                    chosen = Some(body);
                    break;
                }
                Some(false) => {}
                None => return Ok(Flow::Denied),
            }
        }
        let flow = match chosen {
            Some(body) => self.run_block(".if", body)?,
            None => Flow::Continue,
        };
        self.then_rest(flow, statement.rest)
    }

    fn cmd_orphan_else(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        error!(
            "{} must follow the block of an .if or .elsif",
            invocation.name
        );
        Ok(Flow::Denied)
    }

    fn cmd_while(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        self.loop_command(invocation, parse_while)
    }

    fn cmd_for(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        self.loop_command(invocation, parse_for)
    }

    fn cmd_do(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        self.loop_command(invocation, parse_do)
    }

    fn loop_command(
        &mut self,
        invocation: CommandInvocation<'_>,
        parse: fn(&str) -> std::result::Result<LoopStatement<'_>, String>,
    ) -> Result<Flow> {
        let name = invocation.name;
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(name));
            return Ok(Flow::Continue);
        }
        let statement = match parse(invocation.raw_tail) {
            Ok(statement) => statement,
            Err(error) => return Self::malformed(name, error),
        };
        let flow = self.in_command_loop(name, |state| {
            let outer = std::mem::replace(&mut state.breakable_loop, true);
            let flow = state.run_loop(name, &statement);
            state.breakable_loop = outer;
            flow
        })?;
        self.then_rest(flow, statement.rest)
    }

    fn run_loop(&mut self, name: &str, statement: &LoopStatement<'_>) -> Result<Flow> {
        if let Some(init) = statement.init {
            match loop_step(name, self.dispatch_line(init)?) {
                LoopStep::Next => {}
                LoopStep::Leave => return Ok(Flow::Continue),
                LoopStep::Return(flow) => return Ok(flow),
            }
        }
        let mut passes = 0u64;
        loop {
            if self.command_loop_cancelled() {
                outln!("{name}: interrupted after {passes} passes");
                return Ok(Flow::Continue);
            }
            if statement.test_first {
                match self.condition_holds(name, statement.condition) {
                    Some(true) => {}
                    Some(false) => return Ok(Flow::Continue),
                    None => return Ok(Flow::Denied),
                }
            }
            match loop_step(name, self.dispatch_line(statement.body)?) {
                LoopStep::Next => {}
                LoopStep::Leave => return Ok(Flow::Continue),
                LoopStep::Return(flow) => return Ok(flow),
            }
            passes += 1;
            if let Some(step) = statement.step {
                match loop_step(name, self.dispatch_line(step)?) {
                    LoopStep::Next => {}
                    LoopStep::Leave => return Ok(Flow::Continue),
                    LoopStep::Return(flow) => return Ok(flow),
                }
            }
            if !statement.test_first {
                match self.condition_holds(name, statement.condition) {
                    Some(true) => {}
                    Some(false) => return Ok(Flow::Continue),
                    None => return Ok(Flow::Denied),
                }
            }
        }
    }

    fn cmd_break(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        self.loop_jump(invocation, Jump::Break)
    }

    fn cmd_continue(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        self.loop_jump(invocation, Jump::Continue)
    }

    fn loop_jump(&mut self, invocation: CommandInvocation<'_>, jump: Jump) -> Result<Flow> {
        if !invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        if !self.breakable_loop {
            error!(
                "{} is only valid inside a .for, .while, or .do loop",
                invocation.name
            );
            return Ok(Flow::Denied);
        }
        Ok(Flow::Jump(jump))
    }

    fn cmd_block(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        let (body, rest) = match take_block(invocation.raw_tail) {
            Ok(block) => block,
            Err(error) => return Self::malformed(".block", error),
        };
        let flow = self.run_block(".block", body)?;
        self.then_rest(flow, rest)
    }

    fn cmd_j(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        // `*` in an expression multiplies; a comment is never Command1.
        let is_command = |word: &str| {
            (command_registry().get(word).is_some() && !is_comment(word))
                || self
                    .aliases
                    .entries()
                    .iter()
                    .any(|(alias, _)| alias == word)
                || word.starts_with('~')
                || script_file_token(word).is_some()
        };
        let command = match parse_j(invocation.raw_tail, self.radix, is_command) {
            Ok(command) => command,
            Err(error) => return Self::malformed("j", error),
        };
        if !command.ignored.is_empty() {
            print_warning(format!("j: ignoring '{}' after Command2", command.ignored));
        }
        let Some(holds) = self.condition_holds("j", command.condition) else {
            return Ok(Flow::Denied);
        };
        let commands = if holds {
            command.then
        } else {
            command.otherwise
        };
        if commands.trim().is_empty() {
            return Ok(Flow::Continue);
        }
        self.run_block("j", &commands)
    }

    /// Run a script file: `token` is the `$<`-family token, `operand` the
    /// text glued on after it (file name, and arguments for `$$>a<`).
    pub fn run_script_file(&mut self, token: &str, operand: &str) -> Result<Flow> {
        let operand = operand.trim();
        let (path, args) = if token == "$$>a<" {
            let mut words = match parse_args(operand, 0) {
                Ok(words) => words,
                Err(_) => return Self::malformed(token, "unterminated quoted argument".into()),
            };
            if words.is_empty() {
                (Cow::Borrowed(""), words)
            } else {
                let path = words.remove(0);
                (path, words)
            }
        } else {
            (unquote_whole(operand), Vec::new())
        };
        if path.is_empty() {
            outln!("{}\n", command_help("$<"));
            return Ok(Flow::Continue);
        }
        let text = match std::fs::read_to_string(path.as_ref()) {
            Ok(text) => text,
            Err(error) => {
                error!("{token}: failed to read '{path}': {error}");
                return Ok(Flow::Denied);
            }
        };
        let text = if token == "$$>a<" {
            let Ok(text) = substitute(&text, |name| {
                Ok::<_, std::convert::Infallible>(script_argument(&args, name))
            });
            text
        } else {
            text
        };
        let lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let echo = token != "$$>a<";
        self.in_command_loop(token, |state| {
            if matches!(token, "$<" | "$$<") {
                for line in lines {
                    if state.command_loop_cancelled() {
                        outln!("{token}: interrupted");
                        break;
                    }
                    state.echo_script_command(line);
                    match state.dispatch_line(line)? {
                        Flow::Continue => {}
                        flow => return Ok(flow),
                    }
                }
                return Ok(Flow::Continue);
            }
            let block = lines.collect::<Vec<_>>().join(";");
            if echo {
                state.echo_script_command(&block);
            }
            state.dispatch_line(&block)
        })
    }

    /// Echo a script's command after a prompt, as it would appear typed.
    fn echo_script_command(&self, command: &str) {
        let thread = &self.ctx.current_thread;
        let prompt = if thread.is_empty() {
            "ntoseye>".to_string()
        } else {
            format!("{}:{thread}>", self.ctx.backend.name())
        };
        outln!("{} {command}", ui::muted(&prompt));
    }

    /// `r $tN` and `r $tN = expression`: show or set a user pseudo-register.
    /// WinDbg's assignment prints nothing, which a script's loop counter
    /// relies on.
    pub fn cmd_pseudo_register(&mut self, slot: String, value: Option<&str>) {
        let Some(expression) = value else {
            let value = self
                .ctx
                .target
                .user_vars
                .get(&slot)
                .map_or(0, |var| var.value);
            outln!("${slot}={}", ui::addr(value));
            return;
        };
        if expression.is_empty() {
            outln!("{}\n", command_help("r"));
            return;
        }
        let Some(value) = self.eval_or_report(expression) else {
            return;
        };
        self.ctx.target.user_vars.insert(
            slot,
            UserVar {
                value: value.0,
                source: expression.to_string(),
            },
        );
    }

    fn cmd_sleep(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (Some(text), 1) = (invocation.arg(0), invocation.argv.len()) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(milliseconds) = self.eval_or_report(text) else {
            return Ok(());
        };
        let requests = self.ctx.target.interrupt_requests();
        // Past what an Instant can hold, the pause lasts until Ctrl+C.
        let deadline = Instant::now().checked_add(Duration::from_millis(milliseconds.0));
        loop {
            if self.cancelled_since(requests) {
                // The Ctrl+C was for this pause; an enclosing loop still
                // sees it in the request count.
                self.ctx.target.interrupt.store(false, Ordering::SeqCst);
                outln!(".sleep: interrupted");
                return Ok(());
            }
            let slice = match deadline {
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(());
                    }
                    (deadline - now).min(SLEEP_POLL)
                }
                None => SLEEP_POLL,
            };
            std::thread::sleep(slice);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::capture;
    use crate::session::session_over_memory;

    /// Run `line` as a typed line in `context`; its flow and output.
    fn run(line: &str, context: DispatchContext) -> (Flow, String) {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        state.context = context;
        let (flow, text) = capture(|| state.dispatch_line(line));
        (flow.unwrap(), text)
    }

    fn interactive(line: &str) -> (Flow, String) {
        run(line, DispatchContext::Interactive)
    }

    #[test]
    fn if_chain_runs_the_first_holding_block_and_then_the_rest_of_the_line() {
        for (value, expected) in [(1, "one\n"), (2, "two\n"), (3, "other\n")] {
            let (flow, text) = interactive(&format!(
                "r $t0 = {value}; .if (@$t0 == 1) {{ .echo one }} .elsif (@$t0 == 2) {{ .echo two }} .else {{ .echo other }}; .echo after"
            ));
            assert_eq!(flow, Flow::Continue);
            assert_eq!(text, format!("{expected}after\n"));
        }
    }

    #[test]
    fn statements_parse_across_the_semicolons_a_joined_script_leaves() {
        let (flow, text) = interactive(".if (0);{;.echo no;};.else;{;.echo yes;};.echo after");
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "yes\nafter\n");
        let (_, text) = interactive(".if(1){.echo glued}");
        assert_eq!(text, "glued\n");
    }

    #[test]
    fn for_loop_counts_with_a_pseudo_register() {
        let (flow, text) = interactive(
            ".for (r $t0 = 0; @$t0 < 3; r $t0 = @$t0 + 1) { .printf \"%d\\n\" @$t0 }; r $t0",
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "0\n1\n2\n$t0=0000000000000003\n");
    }

    #[test]
    fn break_and_continue_steer_the_innermost_loop_only() {
        // The inner .while breaks at 2 every time; .continue skips odd outer
        // passes; the outer loop runs to its condition.
        let (flow, text) = interactive(
            ".for (r $t0 = 0; @$t0 < 4; r $t0 = @$t0 + 1) { .if (@$t0 & 1) { .continue }; r $t1 = 0; .while (1) { r $t1 = @$t1 + 1; .if (@$t1 == 2) { .break } }; .printf \"%d %d\\n\" @$t0 @$t1 }",
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "0 2\n2 2\n");
    }

    #[test]
    fn do_loop_tests_after_the_body() {
        let (_, text) = interactive("r $t0 = 5; .do { .echo ran; r $t0 = @$t0 + 1 } (@$t0 < 3)");
        assert_eq!(text, "ran\n");
    }

    #[test]
    fn break_outside_a_control_loop_is_refused_even_inside_foreach() {
        let (flow, text) = interactive(".break; .echo after");
        assert_eq!(flow, Flow::Denied);
        assert!(!text.contains("after"), "{text}");
        // WinDbg's .break steers only .for/.while/.do, not .foreach, even
        // one nested in a loop it would steer.
        let (flow, text) =
            interactive(".while (1) { .foreach /s (x \"a b\") { .echo x ; .break } }; .echo after");
        assert_eq!(flow, Flow::Denied);
        assert_eq!(text.matches("error:").count(), 1, "{text}");
        assert!(text.starts_with("a\n") && !text.contains("after"), "{text}");
    }

    #[test]
    fn a_failing_condition_ends_the_loop_and_the_line() {
        let (flow, text) = interactive(".while (nosuchsymbol_xyz) { .echo body }; .echo after");
        assert_eq!(flow, Flow::Denied);
        assert!(!text.contains("body") && !text.contains("after"), "{text}");
    }

    #[test]
    fn j_picks_a_branch_and_quoted_branches_hold_several_commands() {
        let (_, text) = interactive("j (1 == 1) '.echo a; .echo b' ; '.echo c'");
        assert_eq!(text, "a\nb\n");
        let (_, text) = interactive("j 0 .echo a ; .echo c");
        assert_eq!(text, "c\n");
        let (_, text) = interactive("j 1 == 0 ; '.echo only-else'");
        assert_eq!(text, "only-else\n");
        let (_, text) = interactive("j (0) '.echo a'");
        assert_eq!(text, "");
        // `*` multiplies; it does not start a comment as Command1.
        let (_, text) = interactive("j 1 * 0 '.echo yes' ; '.echo no'");
        assert_eq!(text, "no\n");
    }

    #[test]
    fn j_splits_an_unparenthesized_expression_from_an_unquoted_command() {
        let is_command = |word: &str| command_registry().get(word).is_some();
        // `0 .echo` would parse as a member access; the command starts first.
        let command = parse_j("0 .echo ; .echo c", NumberRadix::Hexadecimal, is_command).unwrap();
        assert_eq!((command.condition, command.then.as_ref()), ("0", ".echo"));
        let command = parse_j(
            "@$t0 == 0 r rax; r rbx",
            NumberRadix::Hexadecimal,
            is_command,
        )
        .unwrap();
        assert_eq!(command.condition, "@$t0 == 0");
        assert_eq!(command.then, "r rax");
        assert_eq!(command.otherwise, "r rbx");
        let command = parse_j(
            "(1) 'a;b' ; 'c' ; ignored",
            NumberRadix::Hexadecimal,
            is_command,
        )
        .unwrap();
        assert_eq!(command.then, "a;b");
        assert_eq!(command.otherwise, "c");
        assert_eq!(command.ignored, "ignored");
        assert!(parse_j("(1) 'a' 'b'", NumberRadix::Hexadecimal, is_command).is_err());
        assert!(parse_j("(1) 'a", NumberRadix::Hexadecimal, is_command).is_err());
    }

    #[test]
    fn gc_in_a_j_branch_resumes_from_a_breakpoint_action() {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        let action = "j (@$t0 == 0) 'r $t0 = 1' ; '.echo second; gc'";
        let (first, _) = capture(|| state.dispatch_breakpoint_action(action));
        assert!(!first.unwrap());
        let (second, text) = capture(|| state.dispatch_breakpoint_action(action));
        assert!(second.unwrap());
        assert_eq!(text, "second\n");
        // WinDbg scripts write a plain `g` for the same resume; one with an
        // address is still run control the action may not take.
        let (resumed, text) =
            capture(|| state.dispatch_breakpoint_action("j (1) '.echo x; g; .echo not' ; 'g'"));
        assert!(resumed.unwrap());
        assert_eq!(text, "x\n");
        let (resumed, text) = capture(|| state.dispatch_breakpoint_action("g 1000"));
        assert!(!resumed.unwrap());
        assert!(text.contains("error:"), "{text}");
        // Outside an action, gc has nothing to resume.
        let (flow, _) = capture(|| state.dispatch_line("gc"));
        assert_eq!(flow.unwrap(), Flow::Denied);
    }

    #[test]
    fn a_remote_timeout_ends_an_endless_loop_and_sleep() {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        state.stop_wait = Some(StopWaitBudget::new(
            Duration::from_millis(50),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        let (flow, text) = capture(|| state.dispatch_line(".while (1) { }; .sleep ffffffff"));
        assert_eq!(flow.unwrap(), Flow::Continue);
        assert!(text.starts_with(".while: interrupted"), "{text}");
        assert!(text.ends_with(".sleep: interrupted\n"), "{text}");
    }

    #[test]
    fn parses_loop_headers() {
        let statement = parse_for("(r $t0 = 0; poi(a;b) < 3; r $t0 = @$t0+1){x} ; rest").unwrap();
        assert_eq!(statement.init, Some("r $t0 = 0"));
        assert_eq!(statement.condition, "poi(a;b) < 3");
        assert_eq!(statement.step, Some("r $t0 = @$t0+1"));
        assert_eq!(statement.body, "x");
        assert_eq!(statement.rest, " ; rest");
        for text in ["(a; b) {x}", "(a; ; c) {x}", "(a; b; c)", "(a; \"b; c) {x}"] {
            assert!(parse_for(text).is_err(), "{text} parsed");
        }
        let statement = parse_do("{ x } ; (@$t0 < (2)) tail").unwrap();
        assert_eq!(statement.condition, "@$t0 < (2)");
        assert_eq!(statement.rest, " tail");
        assert!(parse_while("(1 {x}").is_err());
        assert!(parse_if("(1) {x} .else").is_err());
        // `.elsewhere` is not `.else`.
        assert_eq!(parse_if("(1) {x} .elsewhere").unwrap().rest, " .elsewhere");
    }

    #[test]
    fn script_arguments_fill_in_given_ones_and_leave_the_rest() {
        let args = [Cow::Borrowed("first one"), Cow::Borrowed("2")];
        let Ok(text) = substitute(
            ".echo ${$arg1} ${$arg2} ${$arg3}; .if (${/d:$arg2}) {} .if (${/d:$arg3}) {}",
            |name| Ok::<_, std::convert::Infallible>(script_argument(&args, name)),
        );
        assert_eq!(text, ".echo first one 2 ${$arg3}; .if (1) {} .if (0) {}");
    }

    #[test]
    fn script_files_run_line_by_line_or_joined() {
        let dir = std::env::temp_dir().join(format!("ntoseye-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("loop.txt");
        std::fs::write(
            &path,
            "$$ count to ${$arg1}\n.for (r $t0 = 0; @$t0 < ${$arg1}; r $t0 = @$t0 + 1)\n{\n  $$ don't touch rcx\n  .printf \"%d\\n\" @$t0\n}\n",
        )
        .unwrap();
        let (flow, text) = interactive(&format!("$$>a<\"{}\" 2; .echo after", path.display()));
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "0\n1\nafter\n");
        // Line by line, the block's opening line is a statement on its own.
        let (flow, text) = interactive(&format!("$$<{}", path.display()));
        assert_eq!(flow, Flow::Denied);
        assert!(text.contains("error:"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn comments_end_where_windbg_ends_them() {
        let (_, text) = interactive("$$ don't run this; .echo ran; * .echo not; .echo either");
        assert_eq!(text, "ran\n");
        let (_, text) = interactive(".if (1) { $$ don't do this ; .echo x }");
        assert_eq!(text, "x\n");
    }

    #[test]
    fn pseudo_register_operands() {
        assert_eq!(
            pseudo_register_operand("@$T19 = @$t0+1"),
            Some(("t19".to_string(), Some("@$t0+1")))
        );
        assert_eq!(
            pseudo_register_operand("$t0"),
            Some(("t0".to_string(), None))
        );
        assert_eq!(pseudo_register_operand("rax=1"), None);
        assert_eq!(pseudo_register_operand("$t20=1"), None);
        assert_eq!(pseudo_register_operand("$ip"), None);
    }
}
