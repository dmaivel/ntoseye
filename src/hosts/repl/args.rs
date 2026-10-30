//! Typed REPL arguments: what a `#[command]` handler parses its line with.
//! The macro reads the function's parameters in order, each through
//! [`FromArg`] (or a custom parser, `#[arg(parse = f)]`), from an
//! [`ArgCursor`] over the line's words; [`ArgError`] reports a bad line as
//! the hand-written handlers did.

use std::borrow::Cow;

use ntoseye_macros::grammar;

use crate::base::diagnostics::note_error;
use crate::base::types::VirtAddr;
use crate::hosts::repl::{
    CommandInvocation, CompletionStrategy, ReplState, command_help, error, usage_error,
};
use crate::nt::breakpoints::BreakpointId;
use crate::nt::expr::Expr;
use crate::nt::target::MemoryKind;
use crate::nt::target::gflag::GlobalFlagChange;

/// What a parser may use: the REPL (radix, target, caches) and the name the
/// command was typed as.
pub struct ArgCx<'s, 'a> {
    pub state: &'s mut ReplState<'a>,
    pub name: &'s str,
}

impl ArgCx<'_, '_> {
    /// `text` as an expression in the current radix.
    pub fn eval(&self, text: &str) -> Result<VirtAddr, ArgError> {
        Expr::eval_with_radix(text, &self.state.ctx.target, self.state.ctx.radix)
            .map_err(|error| ArgError::Message(error.to_string()))
    }
}

/// Why a line does not parse.
#[derive(Debug)]
pub enum ArgError {
    /// A required argument is missing: the command's help says what it takes.
    Missing,
    /// Reported as an error.
    Message(String),
}

impl ArgError {
    /// `reason`, then command `name`'s generated usage (see
    /// [`usage_error`]).
    pub fn usage(name: &str, reason: impl std::fmt::Display) -> Self {
        Self::Message(usage_error(name, reason))
    }

    pub fn report(&self, name: &str) {
        match self {
            // The help stands in for the error message, but a `;` list must
            // still stop here and MCP must still flag the line as failed.
            Self::Missing => {
                outln!("{}", command_help(name));
                note_error();
            }
            Self::Message(message) => error!("{message}"),
        }
    }
}

/// A value one word of the line names.
pub trait FromArg: Sized {
    /// How the line editor completes the word.
    const COMPLETION: CompletionStrategy = CompletionStrategy::None;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError>;
}

/// A value an omitted `#[arg(current)]` argument takes: the current process,
/// thread, and so on.
pub trait Current: Sized {
    fn current(cx: &mut ArgCx<'_, '_>) -> Result<Self, ArgError>;
}

impl FromArg for VirtAddr {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        cx.eval(text)
    }
}

impl FromArg for u64 {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        cx.eval(text).map(|value| value.0)
    }
}

/// A count (`wt [count]`): an expression that fits the host's word.
impl FromArg for usize {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        let value = cx.eval(text)?.0;
        usize::try_from(value)
            .map_err(|_| ArgError::Message(format!("{}: {text} is too large", cx.name)))
    }
}

impl FromArg for String {
    fn from_arg(_: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        Ok(text.to_string())
    }
}

impl FromArg for BreakpointId {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Breakpoint;

    fn from_arg(_: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        text.parse()
            .map(BreakpointId)
            .map_err(|_| ArgError::Message(format!("invalid breakpoint ID: {text}")))
    }
}

/// `!gflag`'s change, its values in the current radix.
impl FromArg for GlobalFlagChange {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        Self::parse(text, |text| {
            Expr::eval_with_radix(text, &cx.state.ctx.target, cx.state.ctx.radix)
                .map(|value| value.0)
        })
        .map_err(|error| ArgError::Message(error.to_string()))
    }
}

/// `#[arg(receiver, parse = virtual_memory)]`: a virtual-memory command
/// (`db`) addresses the context's address space. It takes no word; the
/// SDK's `Memory` binds the kind from its space.
#[grammar(usage = "")]
pub fn virtual_memory(
    _: &mut ArgCx<'_, '_>,
    _: &mut ArgCursor<'_>,
) -> Result<MemoryKind, ArgError> {
    Ok(MemoryKind::Virtual)
}

/// `#[arg(parse = words)]`: every word left, as written (quotes removed),
/// for a command that takes a list (`undisplay 1 3`), which reads them.
#[grammar(operation)]
pub fn words(_: &mut ArgCx<'_, '_>, cursor: &mut ArgCursor<'_>) -> Result<Vec<String>, ArgError> {
    Ok(cursor
        .take_all(|_| true)
        .into_iter()
        .map(Cow::into_owned)
        .collect())
}

/// The words of a command line not yet parsed. Positional arguments take
/// them front to back; a switch is found anywhere.
pub struct ArgCursor<'i> {
    words: Vec<Option<Cow<'i, str>>>,
    raw_tail: &'i str,
}

impl<'i> ArgCursor<'i> {
    pub fn new(invocation: CommandInvocation<'i>) -> Self {
        Self {
            words: invocation.argv.into_iter().map(Some).collect(),
            raw_tail: invocation.raw_tail,
        }
    }

    /// The line after the command name, trimmed but unsplit, for a grammar
    /// of its own (an alias body, a `.foreach` program, a shell command).
    /// Every word counts as parsed.
    pub fn raw(&mut self) -> String {
        self.words.clear();
        self.raw_tail.to_string()
    }

    /// The next word.
    pub fn word(&mut self) -> Option<Cow<'i, str>> {
        self.words.iter_mut().find_map(Option::take)
    }

    /// The next word, left in place, for a grammar whose next argument
    /// depends on it (`rdmsr /p <processor> <msr>`).
    pub fn peek(&self) -> Option<&str> {
        self.words.iter().flatten().next().map(AsRef::as_ref)
    }

    /// Every word left that `wanted` accepts, in order, taken; the others
    /// stay for the arguments after (`!uniqstack`'s `-v`/`-n` anywhere
    /// before or after its process).
    pub fn take_all(&mut self, wanted: impl Fn(&str) -> bool) -> Vec<Cow<'i, str>> {
        self.words
            .iter_mut()
            .filter(|word| word.as_deref().is_some_and(&wanted))
            .filter_map(Option::take)
            .collect()
    }

    /// The `index`th word left (`word_at(0)` is [`Self::word`]), for a grammar
    /// whose words are not in parameter order (`!process <process> [flags]
    /// [image]` reads the image with the process).
    pub fn word_at(&mut self, index: usize) -> Option<Cow<'i, str>> {
        self.words
            .iter_mut()
            .filter(|word| word.is_some())
            .nth(index)?
            .take()
    }

    /// How many words are left.
    pub fn remaining(&self) -> usize {
        self.words.iter().flatten().count()
    }

    /// The words left, in order, without taking them: for a grammar that
    /// checks the whole line before its parsers take their words
    /// (`!wmitrace.logdump [-t count] <logger>` reports its first bad word,
    /// wherever it is).
    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.words.iter().flatten().map(|word| &**word)
    }

    /// Whether the line has `switch` (any case), which is consumed.
    pub fn switch(&mut self, switch: &str) -> bool {
        let mut found = false;
        for word in &mut self.words {
            if word
                .as_deref()
                .is_some_and(|word| word.eq_ignore_ascii_case(switch))
            {
                *word = None;
                found = true;
            }
        }
        found
    }

    /// Refuse a `/` word left once the command's switches are taken.
    pub fn reject_switches(&self, name: &str, known: &[&str]) -> Result<(), ArgError> {
        match self
            .words
            .iter()
            .flatten()
            .find(|word| word.starts_with('/'))
        {
            Some(word) => Err(ArgError::Message(format!(
                "unknown {name} switch '{word}'; expected {}",
                alternatives(known)
            ))),
            None => Ok(()),
        }
    }

    /// Every word left, joined by spaces.
    pub fn rest(&mut self) -> String {
        let words: Vec<Cow<'i, str>> = self.words.iter_mut().filter_map(Option::take).collect();
        words.join(" ")
    }

    /// Refuse a word nothing parsed.
    pub fn finish(&self, name: &str) -> Result<(), ArgError> {
        match self.words.iter().flatten().next() {
            Some(word) => Err(ArgError::Message(format!(
                "{name}: unexpected argument '{word}'"
            ))),
            None => Ok(()),
        }
    }
}

/// `a`, `a or b`, `a, b, or c`.
fn alternatives(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [first, second] => format!("{first} or {second}"),
        [init @ .., last] => format!("{}, or {last}", init.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::repl::{CommandStyle, parse_command};

    fn cursor(line: &str) -> ArgCursor<'_> {
        let parsed = parse_command(line).unwrap().unwrap();
        ArgCursor::new(parsed.invocation(CommandStyle::StructuredArgs).unwrap())
    }

    #[test]
    fn positionals_switches_and_rest() {
        let mut args = cursor(".process /P 4 /r tail of line");
        assert!(args.switch("/p"));
        assert!(args.switch("/r"));
        assert!(!args.switch("/i"));
        assert!(
            args.reject_switches(".process", &["/i", "/p", "/r"])
                .is_ok()
        );
        assert_eq!(args.word().as_deref(), Some("4"));
        assert_eq!(args.words().collect::<Vec<_>>(), ["tail", "of", "line"]);
        assert_eq!(args.word_at(1).as_deref(), Some("of"));
        assert_eq!(args.remaining(), 2);
        assert_eq!(args.rest(), "tail line");
        assert!(args.finish(".process").is_ok());
    }

    #[test]
    fn leftovers_are_refused() {
        let args = cursor(".process /x 4");
        let Err(ArgError::Message(message)) = args.reject_switches(".process", &["/i", "/p", "/r"])
        else {
            panic!("unknown switch accepted");
        };
        assert_eq!(
            message,
            "unknown .process switch '/x'; expected /i, /p, or /r"
        );
        assert!(
            matches!(args.finish("ps"), Err(ArgError::Message(message)) if message.contains("'/x'"))
        );
    }
}
