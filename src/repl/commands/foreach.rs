//! Command repetition: `.foreach` runs commands once per token of another
//! command's output (or a string, or a file), and `!for_each_process`,
//! `!for_each_thread`, and `!for_each_module` run commands once per process,
//! thread, and module. Every repeated command goes through `dispatch_line`,
//! the path a typed line takes, so its output reaches whichever host is
//! capturing (the REPL, MCP's `command` tool, DAP's evaluate).

use std::convert::Infallible;
use std::sync::atomic::Ordering;

use crate::error::Result;
use crate::expr::Expr;
use crate::guest::ModuleInfo;
use crate::output;
use crate::symbols::ModuleSymbolStatus;
use crate::target::ThreadInfo;

use crate::repl::*;

/// How deeply command loops may nest (a `.foreach` inside a `.foreach`, or an
/// alias that runs a loop over itself).
const COMMAND_LOOP_DEPTH_LIMIT: usize = 16;

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
    cmd_foreach;
    names: [".foreach"],
    usage: ".foreach [/pS n] [/ps n] ( Variable { InCommands } ) { OutCommands } | .foreach [options] /s ( Variable \"InString\" ) { OutCommands } | .foreach [options] /f ( Variable \"InFile\" ) { OutCommands }",
    summary: "Run commands once for each token of a command's output, a string, or a file.",
    details: "InCommands run first with their output hidden; that output (or InString, or the text of InFile) is split at spaces, tabs, and line breaks, and OutCommands run once per token with each whole-word occurrence of Variable replaced by it. Variable must stand alone between spaces (or at an end of OutCommands) to be replaced; `${Variable}` replaces it anywhere, even inside other text. /pS n skips the first n tokens, and /ps n skips n tokens after each one used: `.foreach /pS 2 /ps 4` uses the 3rd, 8th, 13th token... The skip counts are expressions in the current radix. OutCommands can hold several `;`-separated commands, another `.foreach`, or `!for_each_*`. Ctrl+C stops the loop; a command that fails or is refused ends it.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_process;
    names: ["!for_each_process"],
    usage: "!for_each_process [\"CommandString\"]",
    summary: "Run commands once for each process in the target.",
    details: "In CommandString, each whole-word `@#Process` (or `${@#Process}` anywhere) is replaced by the process's EPROCESS address. Several commands are separated by `;` and the string quoted. Without CommandString, runs `!process @#Process 0` for every process. The process context (`.process`, `$proc`) is not changed; `.process /p @#Process` in CommandString switches it, and the switch stays. Processes are the ones `ps` lists, in its order. Ctrl+C stops the loop; a command that fails or is refused ends it.",
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_thread;
    names: ["!for_each_thread"],
    usage: "!for_each_thread [\"CommandString\"]",
    summary: "Run commands once for each thread in the target, or in the `.process` process.",
    details: "In CommandString, each whole-word `@#Thread` (or `${@#Thread}` anywhere) is replaced by the thread's ETHREAD address. Several commands are separated by `;` and the string quoted. Without CommandString, runs `!thread @#Thread 2` for every thread. With a process selected by `.process`, only that process's threads are visited; otherwise every thread `threads` lists. The thread context (`.thread`, `$thread`) is not changed. Ctrl+C stops the loop; a command that fails or is refused ends it.",
    style: ExpressionTail,
}

repl_command! {
    cmd_for_each_module;
    names: ["!for_each_module"],
    usage: "!for_each_module [\"CommandString\"]",
    summary: "Run commands once for each loaded module `lm` lists.",
    details: "Visits the modules of the current scope in `lm` order: the `.process` process's, else the kernel's (the secure kernel's under `.vtl 1`). CommandString may use these aliases, each replaced as a whole word or anywhere as `${@#Name}`, case-sensitively: @#ModuleIndex (0-based position), @#ModuleName (the `module!` name `lm` shows), @#ImageName (the image name `lm` shows), @#LoadedImageName (the loader's full path when known, else the image name), @#SymbolFileName (the local PDB the symbols came from, else the image name), @#Base, @#End, @#Size, @#TimeDateStamp, @#Checksum, @#FileVersion, @#ProductVersion, @#Flags (DEBUG_MODULE_USER_MODE for a process module), @#SymbolType (DEBUG_SYMTYPE_PDB, _DEFERRED while fetching, else _NONE), and @#ModuleNameSize, @#ImageNameSize, @#LoadedImageNameSize, @#SymbolFileNameSize (string length plus one). Numbers are 0x-prefixed hex, so they read the same in any radix. A module lacking a value an alias names (no timestamp, no version resource) is reported and skipped. Without CommandString, runs `.echo @#ModuleIndex : @#Base @#End @#ModuleName @#ImageName  @#LoadedImageName`. Ctrl+C stops the loop; a command that fails or is refused ends it.",
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

fn skip_ws(text: &str) -> &str {
    text.trim_start()
}

/// The quoted string at the start of `text` and what follows it. A backslash
/// escapes only a quote or another backslash, as in command arguments, so
/// Windows paths and `.printf` escapes pass through intact.
fn take_quoted(text: &str) -> std::result::Result<(String, &str), String> {
    let mut chars = text.char_indices();
    let Some((_, quote @ ('"' | '\''))) = chars.next() else {
        return Err("expected a quoted string".to_string());
    };
    let mut value = String::new();
    let mut escaped = false;
    for (index, ch) in chars {
        if escaped {
            if ch != quote && ch != '\\' {
                value.push('\\');
            }
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Ok((value, &text[index + ch.len_utf8()..]));
        } else {
            value.push(ch);
        }
    }
    Err("unterminated quoted string".to_string())
}

/// The contents of the `{ ... }` block at the start of `text` and what
/// follows it. Braces inside quoted strings do not count, so
/// `{ .echo "}" }` is one block.
fn take_block(text: &str) -> std::result::Result<(&str, &str), String> {
    if !text.starts_with('{') {
        return Err("expected '{'".to_string());
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&text[1..index], &text[index + 1..]));
                }
            }
            _ => {}
        }
    }
    Err("unbalanced '{'".to_string())
}

/// A `/pS` or `/ps` count: glued on (`/pS2`) or the next word (`/pS 2`).
fn take_count(text: &str) -> std::result::Result<(&str, &str), String> {
    let text = if text.starts_with(char::is_whitespace) {
        skip_ws(text)
    } else {
        text
    };
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
    let mut rest = skip_ws(tail);
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
        rest = skip_ws(rest);
    }
    if from_string && from_file {
        return Err("/s and /f cannot be combined".to_string());
    }

    let mut rest = skip_ws(
        rest.strip_prefix('(')
            .ok_or("expected '(' before the variable")?,
    );
    let variable_end = rest
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '{' | '"' | '\'' | ')'))
        .unwrap_or(rest.len());
    let variable = &rest[..variable_end];
    if variable.is_empty() {
        return Err("expected a variable name after '('".to_string());
    }
    rest = skip_ws(&rest[variable_end..]);

    let source = if from_string || from_file {
        let (text, after) = take_quoted(rest).map_err(|error| {
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
        let (commands, after) = take_block(rest).map_err(|error| format!("InCommands: {error}"))?;
        rest = after;
        ForeachSource::Commands(commands.trim())
    };

    rest = skip_ws(rest);
    rest = skip_ws(
        rest.strip_prefix(')')
            .ok_or("expected ')' after the input")?,
    );
    let (body, after) = take_block(rest).map_err(|error| format!("OutCommands: {error}"))?;
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
/// aliases require.
fn substitute<E>(
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
            out.push_str(&value);
            index += 2 + close + 1;
            at_word_start = false;
            continue;
        }
        if at_word_start && !ch.is_whitespace() {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if let Some(value) = lookup(&rest[..end])? {
                out.push_str(&value);
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
fn command_string(tail: &str) -> std::result::Result<Option<String>, String> {
    let tail = tail.trim();
    if tail.is_empty() {
        return Ok(None);
    }
    if !tail.starts_with('"') {
        return Ok(Some(tail.to_string()));
    }
    let (command, rest) = take_quoted(tail)?;
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
    /// Enter a command loop, refusing past the nesting limit. The outermost
    /// loop drops a Ctrl+C left over from before it started.
    fn enter_command_loop(&mut self, name: &str) -> bool {
        if self.command_loop_depth >= COMMAND_LOOP_DEPTH_LIMIT {
            error!("{name}: command loops nested more than {COMMAND_LOOP_DEPTH_LIMIT} deep");
            return false;
        }
        if self.command_loop_depth == 0 {
            self.ctx.target.interrupt.store(false, Ordering::SeqCst);
        }
        self.command_loop_depth += 1;
        true
    }

    fn leave_command_loop(&mut self) {
        self.command_loop_depth -= 1;
        // A Ctrl+C that stopped the loops is spent once the outermost ends.
        if self.command_loop_depth == 0 {
            self.ctx.target.interrupt.store(false, Ordering::SeqCst);
        }
    }

    /// Ctrl+C, or a remote host cancelling the call (client gone, shutdown).
    fn command_loop_cancelled(&self) -> bool {
        self.ctx.target.interrupted()
            || self
                .stop_wait
                .as_ref()
                .is_some_and(|budget| budget.cancel.load(Ordering::Relaxed))
    }

    /// Run one iteration's commands; `false` ends the loop.
    fn run_loop_commands(&mut self, name: &str, commands: &str) -> bool {
        match self.dispatch_line(commands) {
            Ok(Flow::Continue) => true,
            Ok(Flow::Denied) => false,
            Ok(Flow::Quit) => {
                error!("{name}: quit is ignored inside a command loop");
                false
            }
            Err(error) => {
                error!("{name}: '{commands}' failed: {error}");
                false
            }
        }
    }

    /// Run `command` once per item, with `aliases(item)` resolving its
    /// names. An item whose aliases cannot all be resolved is reported and
    /// skipped.
    fn repeat_command<T>(
        &mut self,
        name: &str,
        command: &str,
        items: &[T],
        mut aliases: impl FnMut(
            &Self,
            usize,
            &T,
            &str,
        ) -> std::result::Result<Option<String>, MissingValue>,
    ) {
        if !self.enter_command_loop(name) {
            return;
        }
        for (index, item) in items.iter().enumerate() {
            if self.command_loop_cancelled() {
                outln!("{name}: interrupted after {index} of {}", items.len());
                break;
            }
            let expanded = match substitute(command, |alias| aliases(self, index, item, alias)) {
                Ok(expanded) => expanded,
                Err(MissingValue(reason)) => {
                    error!("{name}: skipped: {reason}");
                    continue;
                }
            };
            if !self.run_loop_commands(name, &expanded) {
                break;
            }
        }
        self.leave_command_loop();
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

    fn cmd_foreach(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let spec = match parse_foreach(invocation.raw_tail) {
            Ok(spec) => spec,
            Err(error) => {
                error!(".foreach: {error}");
                return Ok(());
            }
        };
        let (Some(initial_skip), Some(skip)) = (
            self.foreach_count("/pS", spec.initial_skip),
            self.foreach_count("/ps", spec.skip),
        ) else {
            return Ok(());
        };
        if !self.enter_command_loop(".foreach") {
            return Ok(());
        }
        let input = match &spec.source {
            ForeachSource::Commands(commands) => {
                let (flow, text) = output::capture(|| self.dispatch_line(commands));
                match flow {
                    Ok(Flow::Continue) => Some(text),
                    Ok(Flow::Denied) => None,
                    Ok(Flow::Quit) => {
                        error!(".foreach: quit is ignored inside a command loop");
                        None
                    }
                    Err(error) => {
                        error!(".foreach: InCommands '{commands}' failed: {error}");
                        None
                    }
                }
            }
            ForeachSource::String(text) => Some(text.clone()),
            ForeachSource::File(path) => match std::fs::read_to_string(path) {
                Ok(text) => Some(text),
                Err(error) => {
                    error!(".foreach: failed to read '{path}': {error}");
                    None
                }
            },
        };
        if let Some(input) = input {
            let tokens = foreach_tokens(&input, initial_skip, skip);
            for (index, token) in tokens.iter().enumerate() {
                if self.command_loop_cancelled() {
                    outln!(".foreach: interrupted after {index} of {}", tokens.len());
                    break;
                }
                let Ok(commands) = substitute(spec.body, single_alias(spec.variable, token));
                if !self.run_loop_commands(".foreach", &commands) {
                    break;
                }
            }
        }
        self.leave_command_loop();
        Ok(())
    }

    fn cmd_for_each_process(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_PROCESS_COMMAND) else {
            return Ok(());
        };
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("!for_each_process: failed to enumerate processes: {error}");
                return Ok(());
            }
        };
        self.repeat_command(
            invocation.name,
            &command,
            &processes,
            |_, _, process, alias| {
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
            },
        );
        Ok(())
    }

    fn cmd_for_each_thread(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_THREAD_COMMAND) else {
            return Ok(());
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
                return Ok(());
            }
        };
        let thread_alias = |_: &Self, _: usize, thread: &ThreadInfo, alias: &str| {
            Ok((alias == "@#Thread").then(|| hex(thread.ethread.0)))
        };
        self.repeat_command(invocation.name, &command, &threads, thread_alias);
        Ok(())
    }

    fn cmd_for_each_module(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(command) = self.for_each_command(&invocation, DEFAULT_MODULE_COMMAND) else {
            return Ok(());
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
                return Ok(());
            }
        };
        let dtb = self.ctx.target.process_dtb();
        let user_mode = self.ctx.target.attached_process().is_some()
            && !self.ctx.target.in_secure_address_space();
        self.repeat_command(
            invocation.name,
            &command,
            &modules,
            |state, index, module, alias| {
                let symbols = &state.ctx.target.symbols;
                ModuleAliases {
                    index,
                    module,
                    user_mode,
                    symbol_file: symbols
                        .module_pdb_path(dtb, module.base_address)
                        .map(|path| path.display().to_string()),
                    symbol_status: symbols.module_symbol_status(dtb, module.base_address),
                }
                .resolve(alias)
            },
        );
        Ok(())
    }

    /// The command a `!for_each_*` runs: its CommandString, else `default`.
    /// `None` when the invocation was only a help request or malformed.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
