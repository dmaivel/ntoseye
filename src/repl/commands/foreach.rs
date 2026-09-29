//! Command repetition: `.foreach` runs commands once per token of another
//! command's output (or a string, or a file), and `!for_each_process`,
//! `!for_each_thread`, and `!for_each_module` run commands once per process,
//! thread, and module. Every repeated command goes through `dispatch_line`,
//! the path a typed line takes, so its output reaches whichever host is
//! capturing (the REPL, MCP's `command` tool, DAP's evaluate).

use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::atomic::Ordering;

use crate::error::Result;
use crate::expr::Expr;
use crate::guest::ModuleInfo;
use crate::output;
use crate::symbols::ModuleSymbolStatus;
use crate::target::{SelectedFrame, ThreadInfo};

use crate::repl::commands::frames::print_indexed_stacktrace;
use crate::repl::*;

/// How deeply command loops may nest (a `.foreach` inside a `.foreach`, or an
/// alias that runs a loop over itself).
const COMMAND_LOOP_DEPTH_LIMIT: usize = 16;

/// How many frames `!for_each_frame` visits, as many as WinDbg's `k` walks.
const FOR_EACH_FRAME_LIMIT: usize = 256;

/// WinDbg's defaults when `!for_each_*` is given no command.
const DEFAULT_PROCESS_COMMAND: &str = "!process @#Process 0";
const DEFAULT_THREAD_COMMAND: &str = "!thread @#Thread 2";
const DEFAULT_MODULE_COMMAND: &str =
    ".echo @#ModuleIndex : @#Base @#End @#ModuleName @#ImageName  @#LoadedImageName";

// dbgeng's DEBUG_MODULE_USER_MODE and DEBUG_SYMTYPE_* values, which
// `@#Flags` and `@#SymbolType` report as WinDbg does.
const DEBUG_MODULE_USER_MODE: u64 = 0x2;
const DEBUG_SYMTYPE_NONE: u64 = 0;
const DEBUG_SYMTYPE_PDB: u64 = 3;
const DEBUG_SYMTYPE_DEFERRED: u64 = 5;

repl_command! {
    cmd_foreach -> Flow;
    names: [".foreach"],
    usage: ".foreach [/pS n] [/ps n] ( Variable { InCommands } ) { OutCommands } | .foreach [options] /s ( Variable \"InString\" ) { OutCommands } | .foreach [options] /f ( Variable \"InFile\" ) { OutCommands }",
    summary: "Run commands once for each token of a command's output, a string, or a file.",
    details: "InCommands run first, and ntoseye hides their output. ntoseye shows the errors and warnings of InCommands and does not use them as tokens. ntoseye splits the output (or InString, or the text of InFile) into tokens at spaces, tabs, and line breaks. Then OutCommands run once for each token. In each run, the token replaces each whole-word occurrence of Variable. Variable must stand alone between spaces, or at the start or end of OutCommands, for this replacement. The token replaces `${Variable}` anywhere, also inside other text. If a token contains `;` or a quote, ntoseye inserts it as a quoted string. So the token cannot end its command and start a new command. /pS n skips the first n tokens. /ps n skips n tokens after each token that the loop uses. For example, `.foreach /pS 2 /ps 4` uses the 3rd, 8th, 13th token, and so on. The skip counts are expressions in the current radix. OutCommands can contain several commands separated by `;`, another `.foreach`, or `!for_each_*`. Ctrl+C stops the loop. If the session does not permit a command (for example, a resume in a breakpoint action), the loop stops and the rest of the command line does not run. If a command only shows an error, the loop continues.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_process -> Flow;
    names: ["!for_each_process"],
    usage: "!for_each_process [\"CommandString\"]",
    summary: "Run commands once for each process in the target.",
    details: "In CommandString, ntoseye replaces each whole-word `@#Process` with the EPROCESS address of the process. It replaces `${@#Process}` anywhere. To use several commands, separate them with `;` and put the string in quotes. Without CommandString, the command runs `!process @#Process 0` for each process. The loop does not change the process context (`.process`, `$proc`). To change it, use `.process /p @#Process` in CommandString. This change stays after the loop. The loop uses the processes that `ps` shows, in the same order. Ctrl+C stops the loop. If the session does not permit a command (for example, a resume in a breakpoint action), the loop stops and the rest of the command line does not run. If a command only shows an error, the loop continues.",
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_thread -> Flow;
    names: ["!for_each_thread"],
    usage: "!for_each_thread [\"CommandString\"]",
    summary: "Run commands once for each thread in the target, or in the `.process` process.",
    details: "In CommandString, ntoseye replaces each whole-word `@#Thread` with the ETHREAD address of the thread. It replaces `${@#Thread}` anywhere. To use several commands, separate them with `;` and put the string in quotes. Without CommandString, the command runs `!thread @#Thread 2` for each thread. If you select a process with `.process`, the loop uses only the threads of that process. Otherwise, it uses each thread that `threads` shows. The loop does not change the thread context (`.thread`, `$thread`). Ctrl+C stops the loop. If the session does not permit a command (for example, a resume in a breakpoint action), the loop stops and the rest of the command line does not run. If a command only shows an error, the loop continues.",
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_module -> Flow;
    names: ["!for_each_module"],
    usage: "!for_each_module [\"CommandString\"]",
    summary: "Run commands once for each loaded module that `lm` shows.",
    details: "The loop uses the modules of the current scope, in `lm` order. These are the modules of the `.process` process. Without a `.process` process, they are the kernel modules, or the secure kernel modules under `.vtl 1`. CommandString can use the aliases that follow. ntoseye replaces each alias as a whole word, or anywhere as `${@#Name}`. Alias names are case-sensitive. The aliases are @#ModuleIndex (the 0-based position), @#ModuleName (the `module!` name that `lm` shows), @#ImageName (the image name that `lm` shows), @#LoadedImageName (the full path from the loader if known, else the image name), @#SymbolFileName (the local PDB of the symbols, else the image name), @#Base, @#End, @#Size, @#TimeDateStamp, @#Checksum, @#FileVersion, @#ProductVersion, @#Flags (DEBUG_MODULE_USER_MODE for a process module), @#SymbolType (DEBUG_SYMTYPE_PDB, _DEFERRED while ntoseye gets the symbols, else _NONE), and @#ModuleNameSize, @#ImageNameSize, @#LoadedImageNameSize, @#SymbolFileNameSize (the string length plus one). If a value contains `;` or a quote, ntoseye inserts it as a quoted string. So the value cannot end its command and start a new command. Numbers are hex with a 0x prefix, so they are the same in all radixes. If a module does not have a value that an alias uses (for example, no timestamp or no version resource), ntoseye shows an error and skips the module. Without CommandString, the command runs `.echo @#ModuleIndex : @#Base @#End @#ModuleName @#ImageName  @#LoadedImageName`. Ctrl+C stops the loop. If the session does not permit a command (for example, a resume in a breakpoint action), the loop stops and the rest of the command line does not run. If a command only shows an error, the loop continues.",
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_frame -> Flow;
    names: ["!for_each_frame"],
    usage: "!for_each_frame [\"CommandString\"]",
    summary: "Run commands once for each frame of the current stack, with that frame selected.",
    details: "The loop uses the stack that `k` shows, up to 256 frames. For each frame, ntoseye shows the frame as `.frame` does. Then it makes the frame the local context, as `.frame N` does, so `r`, `dv`, and `@$frame` use that frame. Then CommandString runs. To use several commands, separate them with `;` and put the string in quotes. After the loop, the local context is the same as before. Without CommandString, the command lists the frames and their indexes. Ctrl+C stops the loop. If the session does not permit a command (for example, a resume in a breakpoint action), the loop stops and the rest of the command line does not run. If a command only shows an error, the loop continues.",
    run_state: HaltedOrParkedThread,
    style: ExpressionTail,
}

/// Where `.foreach` takes its tokens from.
#[derive(Debug, PartialEq, Eq)]
enum ForeachSource<'a> {
    Commands(&'a str),
    String(String),
    File(String),
}

/// A parsed `.foreach`. The skip counts stay text: they are expressions,
/// evaluated against the target when the loop runs.
#[derive(Debug, PartialEq, Eq)]
struct ForeachSpec<'a> {
    initial_skip: Option<&'a str>,
    skip: Option<&'a str>,
    variable: &'a str,
    source: ForeachSource<'a>,
    body: &'a str,
}

/// A value an alias names that the current item does not have.
struct MissingValue(String);

/// The quoted string at the start of `text` and what follows it, unescaped
/// as command arguments are.
fn quoted_arg(text: &str) -> std::result::Result<(String, &str), String> {
    if !text.starts_with(['"', '\'']) {
        return Err("expected a quoted string".to_string());
    }
    take_quoted(text).ok_or_else(|| "unterminated quoted string".to_string())
}

/// The inside of the `open` ... `close` span at the start of `text` (a `{ }`
/// block, a `( )` condition) and what follows it. Delimiters inside quoted
/// strings do not count, so `{ .echo "}" }` is one block.
pub fn take_delimited(
    text: &str,
    open: char,
    close: char,
) -> std::result::Result<(&str, &str), String> {
    if !text.starts_with(open) {
        return Err(format!("expected '{open}'"));
    }
    let mut depth = 0usize;
    let scan = scan_unquoted(text, |_, ch| {
        if ch == open {
            depth += 1;
        } else if ch == close {
            // The opening delimiter counted first, so this never underflows.
            depth -= 1;
            return depth == 0;
        }
        false
    });
    match scan {
        Unquoted::Stopped(end) => Ok((&text[1..end], &text[end + 1..])),
        Unquoted::End | Unquoted::OpenQuote(_) => Err(format!("unbalanced '{open}'")),
    }
}

/// A `/pS` or `/ps` count: glued on (`/pS2`) or the next word (`/pS 2`).
fn take_count(text: &str) -> std::result::Result<(&str, &str), String> {
    let text = text.trim_start();
    let end = text
        .find(|ch: char| ch.is_whitespace() || ch == '(' || ch == '/')
        .unwrap_or(text.len());
    if end == 0 {
        return Err("expected a count".to_string());
    }
    Ok((&text[..end], &text[end..]))
}

fn parse_foreach(tail: &str) -> std::result::Result<ForeachSpec<'_>, String> {
    let mut initial_skip = None;
    let mut skip = None;
    let mut from_string = false;
    let mut from_file = false;
    let mut rest = tail.trim_start();
    while let Some(option) = rest.strip_prefix('/') {
        // `/pS` and `/ps` differ only in case, so options match exactly.
        if let Some(after) = option.strip_prefix("pS") {
            let (count, after) = take_count(after).map_err(|error| format!("/pS: {error}"))?;
            initial_skip = Some(count);
            rest = after;
        } else if let Some(after) = option.strip_prefix("ps") {
            let (count, after) = take_count(after).map_err(|error| format!("/ps: {error}"))?;
            skip = Some(count);
            rest = after;
        } else if let Some(after) = option
            .strip_prefix('s')
            .filter(|after| !after.starts_with(|ch: char| ch.is_alphanumeric()))
        {
            from_string = true;
            rest = after;
        } else if let Some(after) = option
            .strip_prefix('f')
            .filter(|after| !after.starts_with(|ch: char| ch.is_alphanumeric()))
        {
            from_file = true;
            rest = after;
        } else {
            let name = option
                .split(|ch: char| ch.is_whitespace() || ch == '(')
                .next()
                .unwrap_or_default();
            return Err(format!("unknown option '/{name}'"));
        }
        rest = rest.trim_start();
    }
    if from_string && from_file {
        return Err("/s and /f cannot be combined".to_string());
    }

    let mut rest = rest
        .strip_prefix('(')
        .ok_or("expected '(' before the variable")?
        .trim_start();
    let variable_end = rest
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '{' | '"' | '\'' | ')'))
        .unwrap_or(rest.len());
    let variable = &rest[..variable_end];
    if variable.is_empty() {
        return Err("expected a variable name after '('".to_string());
    }
    rest = rest[variable_end..].trim_start();

    let source = if from_string || from_file {
        let (text, after) = quoted_arg(rest).map_err(|error| {
            let what = if from_file {
                "/f file name"
            } else {
                "/s string"
            };
            format!("{what}: {error}")
        })?;
        rest = after;
        if from_file {
            ForeachSource::File(text)
        } else {
            ForeachSource::String(text)
        }
    } else {
        let (commands, after) =
            take_delimited(rest, '{', '}').map_err(|error| format!("InCommands: {error}"))?;
        rest = after;
        ForeachSource::Commands(commands.trim())
    };

    rest = rest
        .trim_start()
        .strip_prefix(')')
        .ok_or("expected ')' after the input")?
        .trim_start();
    let (body, after) =
        take_delimited(rest, '{', '}').map_err(|error| format!("OutCommands: {error}"))?;
    if !after.trim().is_empty() {
        return Err(format!(
            "unexpected text after OutCommands: '{}'",
            after.trim()
        ));
    }
    Ok(ForeachSpec {
        initial_skip,
        skip,
        variable,
        source,
        body: body.trim(),
    })
}

/// The tokens `.foreach` hands on: split at any run of spaces, tabs, and line
/// breaks; the first `initial_skip` dropped, then `skip` dropped after each
/// one kept. Quotes in the input group nothing, as in WinDbg.
fn foreach_tokens(input: &str, initial_skip: usize, skip: usize) -> Vec<&str> {
    input
        .split_whitespace()
        .skip(initial_skip)
        .step_by(skip.saturating_add(1))
        .collect()
}

/// Replace names in `text`: a whitespace-delimited word that `lookup`
/// resolves, and `${name}` anywhere. Other text, including a name glued to
/// punctuation, stays as it is, as WinDbg's `.foreach` and `!for_each_*`
/// aliases require. A value holding `;` or a quote goes in quoted (see
/// [`splice_value`]): tokens and module names come from the guest, and one
/// named `x;g` must not resume it.
pub fn substitute<E>(
    text: &str,
    mut lookup: impl FnMut(&str) -> std::result::Result<Option<String>, E>,
) -> std::result::Result<String, E> {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut at_word_start = true;
    while let Some(ch) = text[index..].chars().next() {
        let rest = &text[index..];
        if let Some(inner) = rest.strip_prefix("${")
            && let Some(close) = inner.find('}')
            && let Some(value) = lookup(&inner[..close])?
        {
            out.push_str(&splice_value(&value));
            index += 2 + close + 1;
            at_word_start = false;
            continue;
        }
        if at_word_start && !ch.is_whitespace() {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if let Some(value) = lookup(&rest[..end])? {
                out.push_str(&splice_value(&value));
                index += end;
                at_word_start = false;
                continue;
            }
        }
        out.push(ch);
        index += ch.len_utf8();
        at_word_start = ch.is_whitespace();
    }
    Ok(out)
}

/// A `!for_each_*` CommandString: the tail unquoted when it is one quoted
/// string, else the tail as it is; `None` for none.
pub fn command_string(tail: &str) -> std::result::Result<Option<String>, String> {
    let tail = tail.trim();
    if tail.is_empty() {
        return Ok(None);
    }
    if !tail.starts_with('"') {
        return Ok(Some(tail.to_string()));
    }
    let (command, rest) = quoted_arg(tail)?;
    if !rest.trim().is_empty() {
        return Err(format!(
            "unexpected text after the quoted command: '{}'",
            rest.trim()
        ));
    }
    Ok(Some(command))
}

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

/// Loaded-module name plus one, as dbgeng's `*NameSize` fields count it.
fn name_size(name: &str) -> String {
    hex(name.chars().count() as u64 + 1)
}

/// What each `!for_each_module` alias stands for, for one module.
struct ModuleAliases<'a> {
    index: usize,
    module: &'a ModuleInfo,
    user_mode: bool,
    symbol_file: Option<String>,
    symbol_status: Option<ModuleSymbolStatus>,
}

impl ModuleAliases<'_> {
    fn loaded_image_name(&self) -> &str {
        self.module.path.as_deref().unwrap_or(&self.module.name)
    }

    fn symbol_file_name(&self) -> &str {
        self.symbol_file.as_deref().unwrap_or(&self.module.name)
    }

    fn missing(&self, what: &str) -> MissingValue {
        MissingValue(format!("{} has no readable {what}", self.module.name))
    }

    fn resolve(&self, name: &str) -> std::result::Result<Option<String>, MissingValue> {
        let module = self.module;
        Ok(Some(match name {
            "@#ModuleIndex" => hex(self.index as u64),
            "@#ModuleName" => module.short_name.clone(),
            "@#ImageName" => module.name.clone(),
            "@#LoadedImageName" => self.loaded_image_name().to_string(),
            "@#SymbolFileName" => self.symbol_file_name().to_string(),
            "@#ModuleNameSize" => name_size(&module.short_name),
            "@#ImageNameSize" => name_size(&module.name),
            "@#LoadedImageNameSize" => name_size(self.loaded_image_name()),
            "@#SymbolFileNameSize" => name_size(self.symbol_file_name()),
            "@#Base" => hex(module.base_address.0),
            "@#End" => hex(module.end_address().0),
            "@#Size" => hex(u64::from(module.size)),
            "@#TimeDateStamp" => hex(u64::from(
                module
                    .time_date_stamp
                    .ok_or_else(|| self.missing("TimeDateStamp"))?,
            )),
            "@#Checksum" => hex(u64::from(
                module.checksum.ok_or_else(|| self.missing("checksum"))?,
            )),
            "@#FileVersion" => module
                .file_version
                .clone()
                .ok_or_else(|| self.missing("file version"))?,
            "@#ProductVersion" => module
                .product_version
                .clone()
                .ok_or_else(|| self.missing("product version"))?,
            "@#Flags" => hex(if self.user_mode {
                DEBUG_MODULE_USER_MODE
            } else {
                0
            }),
            "@#SymbolType" => hex(match self.symbol_status {
                Some(ModuleSymbolStatus::Loaded) => DEBUG_SYMTYPE_PDB,
                Some(ModuleSymbolStatus::Fetching) => DEBUG_SYMTYPE_DEFERRED,
                _ => DEBUG_SYMTYPE_NONE,
            }),
            _ => return Ok(None),
        }))
    }
}

fn single_alias<'a>(
    alias: &'a str,
    value: &'a str,
) -> impl FnMut(&str) -> std::result::Result<Option<String>, Infallible> + 'a {
    move |name| Ok((name == alias).then(|| value.to_string()))
}

impl ReplState<'_> {
    /// Run `body` as one command loop. Past the nesting limit the loop is
    /// refused, and the refusal ends every loop around it. The outermost loop
    /// drops a Ctrl+C left over from before it started and counts only the
    /// ones after, unless a breakpoint action or exception command runs it:
    /// a Ctrl+C then is for the stop loop that ran the action, to break in.
    pub(super) fn in_command_loop(
        &mut self,
        name: &str,
        body: impl FnOnce(&mut Self) -> Result<Flow>,
    ) -> Result<Flow> {
        if self.command_loop_depth >= COMMAND_LOOP_DEPTH_LIMIT {
            error!("{name}: command loops nested more than {COMMAND_LOOP_DEPTH_LIMIT} deep");
            return Ok(Flow::Denied);
        }
        let owns_interrupt = self.command_loop_depth == 0 && self.event_command_depth == 0;
        if owns_interrupt {
            self.ctx.target.interrupt.store(false, Ordering::SeqCst);
        }
        if self.command_loop_depth == 0 {
            self.command_loop_interrupts = self.ctx.target.interrupt_requests();
        }
        self.command_loop_depth += 1;
        let flow = body(self);
        self.command_loop_depth -= 1;
        // A Ctrl+C that stopped the loops is spent once the outermost ends.
        if owns_interrupt {
            self.ctx.target.interrupt.store(false, Ordering::SeqCst);
        }
        flow
    }

    /// Ctrl+C since the outermost loop began (even one a command inside took
    /// to stop itself), or a remote call's cancellation (client gone,
    /// shutdown) or elapsed timeout.
    pub fn command_loop_cancelled(&self) -> bool {
        self.cancelled_since(self.command_loop_interrupts)
    }

    /// Ctrl+C since [`Target::interrupt_requests`] read `requests`, or a
    /// remote call's cancellation or elapsed timeout.
    pub fn cancelled_since(&self, requests: u64) -> bool {
        self.ctx.target.interrupt_requests() != requests
            || self
                .stop_wait
                .as_ref()
                .is_some_and(StopWaitBudget::exhausted)
    }

    /// Run `count` iterations of a loop, each dispatching the commands
    /// `commands(state, index)` gives; `None` skips the iteration. Ctrl+C
    /// stops the loop between iterations. A refused command ends it and is
    /// passed on, so the rest of the line is abandoned as it is for a
    /// refused command typed alone; so is an internal error, and a `gc`
    /// resuming from the breakpoint whose action runs the loop. `.break` and
    /// `.continue` steer only `.for`/`.while`/`.do`, so not this loop.
    pub(super) fn run_iterations<'c>(
        &mut self,
        name: &str,
        count: usize,
        mut commands: impl FnMut(&mut Self, usize) -> Option<Cow<'c, str>>,
    ) -> Result<Flow> {
        let breakable = std::mem::replace(&mut self.breakable_loop, false);
        let flow = (|| {
            for index in 0..count {
                if self.command_loop_cancelled() {
                    outln!("{name}: interrupted after {index} of {count}");
                    break;
                }
                let Some(commands) = commands(self, index) else {
                    continue;
                };
                match self.dispatch_line(&commands)? {
                    Flow::Continue => {}
                    Flow::Quit => {
                        error!("{name}: quit is ignored inside a command loop");
                        return Ok(Flow::Denied);
                    }
                    flow => return Ok(flow),
                }
            }
            Ok(Flow::Continue)
        })();
        self.breakable_loop = breakable;
        flow
    }

    /// Run `command` once per item, with the resolver `aliases` builds for
    /// each item replacing its names. An item whose aliases cannot all be
    /// resolved is reported and skipped.
    fn repeat_command<'i, T, A>(
        &mut self,
        name: &str,
        command: &str,
        items: &'i [T],
        mut aliases: impl FnMut(&Self, usize, &'i T) -> A,
    ) -> Result<Flow>
    where
        A: FnMut(&str) -> std::result::Result<Option<String>, MissingValue>,
    {
        self.in_command_loop(name, |state| {
            state.run_iterations(name, items.len(), |state, index| {
                match substitute(command, aliases(state, index, &items[index])) {
                    Ok(expanded) => Some(Cow::Owned(expanded)),
                    Err(MissingValue(reason)) => {
                        error!("{name}: skipped: {reason}");
                        None
                    }
                }
            })
        })
    }

    /// A skip count: an expression in the current radix.
    fn foreach_count(&self, option: &str, text: Option<&str>) -> Option<usize> {
        let Some(text) = text else {
            return Some(0);
        };
        match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(value) => match usize::try_from(value.0) {
                Ok(count) => Some(count),
                Err(_) => {
                    error!(".foreach: {option} count {text} is too large");
                    None
                }
            },
            Err(error) => {
                error!(".foreach: {option} count '{text}': {error}");
                None
            }
        }
    }

    fn cmd_foreach(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        let spec = match parse_foreach(invocation.raw_tail) {
            Ok(spec) => spec,
            Err(error) => {
                error!(".foreach: {error}");
                return Ok(Flow::Continue);
            }
        };
        let (Some(initial_skip), Some(skip)) = (
            self.foreach_count("/pS", spec.initial_skip),
            self.foreach_count("/ps", spec.skip),
        ) else {
            return Ok(Flow::Continue);
        };
        self.in_command_loop(".foreach", |state| {
            let input = match &spec.source {
                ForeachSource::Commands(commands) => {
                    // Only regular output becomes tokens: errors and warnings
                    // reach the user, not OutCommands.
                    let breakable = std::mem::replace(&mut state.breakable_loop, false);
                    let (flow, text) = output::capture_output(|| state.dispatch_line(commands));
                    state.breakable_loop = breakable;
                    if !matches!(flow, Ok(Flow::Continue)) {
                        // The InCommands did not finish: show what they said,
                        // since their refusal or failure is in it.
                        out!("{text}");
                    }
                    match flow? {
                        Flow::Continue => Cow::Owned(text),
                        Flow::Quit => {
                            error!(".foreach: quit is ignored inside a command loop");
                            return Ok(Flow::Denied);
                        }
                        flow => return Ok(flow),
                    }
                }
                ForeachSource::String(text) => Cow::Borrowed(text.as_str()),
                ForeachSource::File(path) => match std::fs::read_to_string(path) {
                    Ok(text) => Cow::Owned(text),
                    Err(error) => {
                        error!(".foreach: failed to read '{path}': {error}");
                        return Ok(Flow::Continue);
                    }
                },
            };
            let tokens = foreach_tokens(&input, initial_skip, skip);
            state.run_iterations(".foreach", tokens.len(), |_, index| {
                let Ok(commands) =
                    substitute(spec.body, single_alias(spec.variable, tokens[index]));
                Some(Cow::Owned(commands))
            })
        })
    }

    fn cmd_for_each_process(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_PROCESS_COMMAND) else {
            return Ok(Flow::Continue);
        };
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("!for_each_process: failed to enumerate processes: {error}");
                return Ok(Flow::Continue);
            }
        };
        self.repeat_command(invocation.name, &command, &processes, |_, _, process| {
            move |alias: &str| {
                if alias != "@#Process" {
                    return Ok(None);
                }
                // A triage dump's one-process snapshot has no EPROCESS address.
                if process.eprocess_va.is_zero() {
                    return Err(MissingValue(format!(
                        "{} (PID {}) has no known EPROCESS address",
                        process.name, process.pid
                    )));
                }
                Ok(Some(hex(process.eprocess_va.0)))
            }
        })
    }

    fn cmd_for_each_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_THREAD_COMMAND) else {
            return Ok(Flow::Continue);
        };
        let threads = match self.ctx.target.attached_process().cloned() {
            Some(process) => self
                .ctx
                .target
                .enumerate_threads_for_process_info(&process)
                .map_err(|error| format!("{} (PID {}): {error}", process.name, process.pid)),
            None => self
                .ctx
                .windows_threads()
                .map(|(threads, _)| threads)
                .map_err(|error| error.to_string()),
        };
        let threads = match threads {
            Ok(threads) => threads,
            Err(error) => {
                error!("!for_each_thread: failed to enumerate threads: {error}");
                return Ok(Flow::Continue);
            }
        };
        self.repeat_command(
            invocation.name,
            &command,
            &threads,
            |_, _, thread: &ThreadInfo| {
                move |alias: &str| Ok((alias == "@#Thread").then(|| hex(thread.ethread.0)))
            },
        )
    }

    fn cmd_for_each_module(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_MODULE_COMMAND) else {
            return Ok(Flow::Continue);
        };
        // Version resources cost reads per module; only fetch them for a
        // command that names them.
        let versions = command.contains("@#FileVersion") || command.contains("@#ProductVersion");
        let modules = if versions {
            self.ctx.target.modules_with_versions()
        } else {
            self.ctx.target.modules()
        };
        let modules = match modules {
            Ok(modules) => modules,
            Err(error) => {
                error!("!for_each_module: failed to list modules: {error}");
                return Ok(Flow::Continue);
            }
        };
        let dtb = self.ctx.target.process_dtb();
        let user_mode = self.ctx.target.attached_process().is_some()
            && !self.ctx.target.in_secure_address_space();
        self.repeat_command(
            invocation.name,
            &command,
            &modules,
            |state, index, module| {
                let symbols = &state.ctx.target.symbols;
                let aliases = ModuleAliases {
                    index,
                    module,
                    user_mode,
                    symbol_file: symbols
                        .module_pdb_path(dtb, module.base_address)
                        .map(|path| path.display().to_string()),
                    symbol_status: symbols.module_symbol_status(dtb, module.base_address),
                };
                move |alias: &str| aliases.resolve(alias)
            },
        )
    }

    /// The command a `!for_each_*` runs: its CommandString, else `default`
    /// (`""` for none). `None` when the invocation was only a help request or
    /// malformed.
    fn for_each_command(
        &self,
        invocation: &CommandInvocation<'_>,
        default: &str,
    ) -> Option<String> {
        if invocation.raw_tail == "-?" {
            outln!("{}\n", command_help(invocation.name));
            return None;
        }
        match command_string(invocation.raw_tail) {
            Ok(command) => Some(command.unwrap_or_else(|| default.to_string())),
            Err(error) => {
                error!("{}: {error}", invocation.name);
                None
            }
        }
    }

    fn cmd_for_each_frame(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        let Some(command) = self.for_each_command(&invocation, "") else {
            return Ok(Flow::Continue);
        };
        let Some((trace, seed, live)) = self.recovered_trace(FOR_EACH_FRAME_LIMIT)? else {
            return Ok(Flow::Continue);
        };
        let previous = self.ctx.target.selected_frame.clone();
        if command.is_empty() {
            let selected = previous.as_ref().map(|frame| frame.index);
            print_indexed_stacktrace(
                &trace,
                FOR_EACH_FRAME_LIMIT,
                0,
                crate::repl::disasm::StackColumns::default(),
                selected,
            );
            outln!();
            return Ok(Flow::Continue);
        }
        let name = invocation.name;
        let flow = self.in_command_loop(name, |state| {
            state.run_iterations(name, trace.frames.len(), |state, index| {
                let Some(frame) = SelectedFrame::from_recovered(&trace, index, Some(&seed), live)
                else {
                    error!("{name}: skipped: frame {index} is unavailable");
                    return None;
                };
                state.ctx.select_frame(frame.clone());
                state.print_selected_frame(&frame, false);
                Some(Cow::Borrowed(command.as_str()))
            })
        });
        match previous {
            Some(frame) => self.ctx.select_frame(frame),
            None => self.ctx.clear_selected_frame(),
        }
        flow
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

    #[test]
    fn out_commands_keep_their_semicolons_and_the_line_goes_on_once() {
        let (flow, text) = run(
            ".foreach /s (x \"a b\") {.echo x ; .echo -}; .echo done",
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "a\n-\nb\n-\ndone\n");
    }

    #[test]
    fn nested_loops_run_the_inner_loop_per_outer_token() {
        let (flow, text) = run(
            ".foreach /s (x \"1 2\") {.foreach /s (y \"a b\") {.echo x y}}",
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "1 a\n1 b\n2 a\n2 b\n");
    }

    #[test]
    fn a_token_holding_a_semicolon_stays_one_argument() {
        let (flow, text) = run(
            ".foreach /s (x \"a;.echo injected\") {.echo x}",
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text, "a;.echo\ninjected\n");
    }

    #[test]
    fn in_command_errors_are_shown_and_not_used_as_tokens() {
        // The malformed inner `.foreach` reports an error and carries on.
        let (flow, text) = run(
            ".foreach (x {.echo a b; .foreach bad}) {.echo x}",
            DispatchContext::Interactive,
        );
        assert_eq!(flow, Flow::Continue);
        assert_eq!(text.matches("error:").count(), 1, "{text}");
        assert!(
            text.starts_with("error:") && text.ends_with("\na\nb\n"),
            "{text}"
        );
    }

    #[test]
    fn a_refused_command_ends_the_loop_and_the_line() {
        // A breakpoint action may not step; the refused `p` must stop the
        // loop and the rest of the line, as it would typed alone.
        let (flow, text) = run(
            ".foreach /s (x \"1 2\") {.echo x ; p}; .echo after",
            DispatchContext::BreakpointAction,
        );
        assert_eq!(flow, Flow::Denied);
        assert!(text.starts_with("1\n"), "{text}");
        assert!(!text.contains("2\n") && !text.contains("after"), "{text}");
    }

    #[test]
    fn the_nesting_limit_ends_every_enclosing_loop() {
        let depth = COMMAND_LOOP_DEPTH_LIMIT + 1;
        let mut line = ".echo innermost".to_string();
        for _ in 0..depth {
            line = format!(".foreach /s (x \"1 2\") {{{line}}}");
        }
        line.push_str("; .echo after");
        let (flow, text) = run(&line, DispatchContext::Interactive);
        assert_eq!(flow, Flow::Denied);
        assert_eq!(text.matches("error:").count(), 1, "{text}");
        assert!(
            !text.contains("innermost") && !text.contains("after"),
            "{text}"
        );
    }

    #[test]
    fn ctrl_c_taken_by_a_command_inside_still_ends_the_loop() {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        let ctrl_c = state.ctx.target.interrupt_requester();
        // Left over from before the loop: ignored.
        ctrl_c.raise();
        let (flow, text) = capture(|| {
            state.in_command_loop("loop", |state| {
                state.run_iterations("loop", 3, |state, index| {
                    if index == 0 {
                        // Pressed during the first iteration, whose command
                        // took the flag to stop itself, as a stack walk does.
                        ctrl_c.raise();
                        state.ctx.target.interrupt.store(false, Ordering::SeqCst);
                    }
                    Some(Cow::Borrowed(".echo ran"))
                })
            })
        });
        assert_eq!(flow.unwrap(), Flow::Continue);
        assert_eq!(text.matches("ran").count(), 1, "{text}");
    }

    fn sub(text: &str, var: &str, value: &str) -> String {
        let Ok(out) = substitute(text, single_alias(var, value));
        out
    }

    #[test]
    fn substitution_replaces_whole_words_only() {
        assert_eq!(sub(".echo p", "p", "0x10"), ".echo 0x10");
        assert_eq!(sub("p", "p", "x"), "x");
        assert_eq!(
            sub("dq p l1; !pool p", "p", "0x10"),
            "dq 0x10 l1; !pool 0x10"
        );
        // Glued to other text, even punctuation, it stays: WinDbg's rule.
        assert_eq!(
            sub("dq (p) pp p; .echo \"p\"", "p", "Z"),
            "dq (p) pp p; .echo \"p\""
        );
        // Tabs and line breaks delimit words too.
        assert_eq!(sub("r\tp\np", "p", "Z"), "r\tZ\nZ");
        // A quoted string's inner words are words.
        assert_eq!(sub(".echo \"a p b\"", "p", "Z"), ".echo \"a Z b\"");
    }

    #[test]
    fn substitution_expands_braced_names_anywhere() {
        assert_eq!(
            sub("x ${@#ModuleName}!*Debug*", "@#ModuleName", "nt"),
            "x nt!*Debug*"
        );
        assert_eq!(sub("dq(${p}+8)", "p", "0x10"), "dq(0x10+8)");
        // An unknown or unterminated `${` is left alone.
        assert_eq!(sub("${q} ${p", "p", "Z"), "${q} ${p");
    }

    #[test]
    fn substitution_does_not_rescan_replacements() {
        assert_eq!(sub("p", "p", "p p"), "p p");
        assert_eq!(sub("${p}", "p", "${p}"), "${p}");
    }

    #[test]
    fn substitution_quotes_values_that_would_end_the_command() {
        assert_eq!(sub(".echo p", "p", "x;g"), r#".echo "x;g""#);
        assert_eq!(sub("dq ${p}", "p", r#"a"b\"#), r#"dq "a\"b\\""#);
        assert_eq!(sub(".echo p", "p", "it's"), r#".echo "it's""#);
        // Plain values, paths with spaces included, go in as they are.
        assert_eq!(
            sub(".echo p", "p", r"C:\Program Files\a.dll"),
            r".echo C:\Program Files\a.dll"
        );
    }

    #[test]
    fn tokens_split_on_any_whitespace_run_and_ignore_quotes() {
        assert_eq!(
            foreach_tokens("  a\tb\r\n\"c d\"  \n", 0, 0),
            vec!["a", "b", "\"c", "d\""]
        );
        assert!(foreach_tokens(" \n\t", 0, 0).is_empty());
    }

    #[test]
    fn tokens_honour_initial_and_repeated_skips() {
        let input = (1..=25)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        // WinDbg's example: /pS 2 /ps 4 uses the 3rd, 8th, 13th... token.
        assert_eq!(
            foreach_tokens(&input, 2, 4),
            vec!["3", "8", "13", "18", "23"]
        );
        assert_eq!(foreach_tokens("a b c", 1, 0), vec!["b", "c"]);
        assert_eq!(foreach_tokens("a b c", 0, 1), vec!["a", "c"]);
        assert!(foreach_tokens("a b c", 3, 0).is_empty());
        assert_eq!(foreach_tokens("a b", 0, usize::MAX), vec!["a"]);
    }

    #[test]
    fn parses_command_source_with_options() {
        let spec = parse_foreach("/pS 1 /ps2 ( m { lm } ) { .echo m; r }").unwrap();
        assert_eq!(
            spec,
            ForeachSpec {
                initial_skip: Some("1"),
                skip: Some("2"),
                variable: "m",
                source: ForeachSource::Commands("lm"),
                body: ".echo m; r",
            }
        );
    }

    #[test]
    fn parses_without_spaces_and_with_nested_blocks() {
        let spec = parse_foreach("(p {ps}) {.foreach (q {.echo p}) {.echo q}}").unwrap();
        assert_eq!(spec.variable, "p");
        assert_eq!(spec.source, ForeachSource::Commands("ps"));
        assert_eq!(spec.body, ".foreach (q {.echo p}) {.echo q}");
    }

    #[test]
    fn braces_inside_quotes_do_not_close_a_block() {
        let spec = parse_foreach(r#"(v {.echo "}{"}) {.printf "{%p}\n", v}"#).unwrap();
        assert_eq!(spec.source, ForeachSource::Commands(r#".echo "}{""#));
        assert_eq!(spec.body, r#".printf "{%p}\n", v"#);
    }

    #[test]
    fn parses_string_and_file_sources() {
        let spec = parse_foreach(r#"/s (v "a \"b\" c") {.echo v}"#).unwrap();
        assert_eq!(spec.source, ForeachSource::String(r#"a "b" c"#.to_string()));
        let spec =
            parse_foreach(r#"/pS 2 /f ( place "C:\dir with space\f.txt") { dds place }"#).unwrap();
        assert_eq!(
            spec.source,
            ForeachSource::File(r"C:\dir with space\f.txt".to_string())
        );
        assert_eq!(spec.initial_skip, Some("2"));
        assert_eq!(spec.body, "dds place");
    }

    #[test]
    fn rejects_malformed_foreach() {
        for text in [
            "p {ps} {x}",
            "( {ps}) {x}",
            "(p ps) {x}",
            "(p {ps) {x}",
            "(p {ps} {x}",
            "(p {ps})",
            "(p {ps}) {x} y",
            "/s (p {ps}) {x}",
            "/s (p \"a) {x}",
            "/pS (p {ps}) {x}",
            "/x (p {ps}) {x}",
            "/s /f (p \"a\") {x}",
        ] {
            assert!(parse_foreach(text).is_err(), "{text} parsed");
        }
    }

    #[test]
    fn command_string_unquotes_one_quoted_string() {
        assert_eq!(command_string("  ").unwrap(), None);
        assert_eq!(
            command_string(r#"".echo @#Process; r""#).unwrap(),
            Some(".echo @#Process; r".to_string())
        );
        assert_eq!(
            command_string(r#"".printf \"%p\\n\", @#Base""#).unwrap(),
            Some(r#".printf "%p\n", @#Base"#.to_string())
        );
        assert_eq!(
            command_string("!chkimg @#ModuleName").unwrap(),
            Some("!chkimg @#ModuleName".to_string())
        );
        assert!(command_string(r#"".echo" extra"#).is_err());
        assert!(command_string(r#"".echo"#).is_err());
    }
}
