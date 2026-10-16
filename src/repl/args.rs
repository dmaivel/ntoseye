//! Typed REPL arguments: what a `#[command]` handler parses its line with.
//! The macro reads the function's parameters in order, each through
//! [`FromArg`] (or a custom parser, `#[arg(parse = f)]`), from an
//! [`ArgCursor`] over the line's words; [`ArgError`] reports a bad line as
//! the hand-written handlers did.

use std::borrow::Cow;

use crate::expr::Expr;
use crate::repl::{CommandInvocation, CompletionStrategy, ReplState, command_help, error};
use crate::types::VirtAddr;

/// What a parser may use: the REPL (radix, target, caches) and the name the
/// command was typed as.
pub struct ArgCx<'s, 'a> {
    pub state: &'s mut ReplState<'a>,
    pub name: &'s str,
}

impl ArgCx<'_, '_> {
    /// `text` as an expression in the current radix.
    pub fn eval(&self, text: &str) -> Result<VirtAddr, ArgError> {
        Expr::eval_with_radix(text, &self.state.ctx.target, self.state.radix)
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
    pub fn report(&self, name: &str) {
        match self {
            Self::Missing => outln!("{}\n", command_help(name)),
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

impl FromArg for String {
    fn from_arg(_: &mut ArgCx<'_, '_>, text: &str) -> Result<Self, ArgError> {
        Ok(text.to_string())
    }
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
    use crate::repl::{CommandStyle, parse_command};

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
