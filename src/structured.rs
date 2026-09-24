//! REPL command line → structured [`View`], for hosts that want typed values
//! (the MCP `command` tool's `format=json`). Each arm evaluates the line's
//! arguments with the REPL's expression grammar and radix, then calls the same
//! core function and `view` builder the Python SDK method uses, so the three
//! surfaces cannot drift. Commands without a structured decoding return
//! `None` and the caller falls back to the text renderer.

mod cpu;
mod execution;
mod heap;
mod meta;
mod mm;
mod object;
mod pnp;
mod process;
mod sched;
mod security;
mod symbols;
mod usermode;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::{CommandStyle, ReplState, parse_command};
use crate::target::Target;
use crate::types::VirtAddr;
use crate::view::View;

/// A domain's decoder: the structured result for the command names it owns,
/// or `None` for every other name.
type Handler = fn(&str, &mut Args<'_, '_>) -> Option<Result<View>>;

/// Every domain's decoder; command names are disjoint across domains.
const HANDLERS: [Handler; 12] = [
    object::command,
    process::command,
    execution::command,
    symbols::command,
    cpu::command,
    sched::command,
    usermode::command,
    heap::command,
    mm::command,
    security::command,
    pnp::command,
    meta::command,
];

/// Dispatch `line` to its structured decoding, if it has one.
pub fn structured_command(state: &mut ReplState<'_>, line: &str) -> Option<Result<View>> {
    let parsed = match parse_command(line) {
        Ok(Some(parsed)) => parsed,
        _ => return None,
    };
    let invocation = parsed.invocation(CommandStyle::StructuredArgs).ok()?;
    let argv: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
    let name = parsed.name;
    let mut args = Args {
        state,
        argv: &argv,
        raw_tail: parsed.raw_tail.trim(),
    };
    HANDLERS.iter().find_map(|command| command(name, &mut args))
}

/// The parsed line plus the evaluation context its arguments need.
struct Args<'s, 'a> {
    state: &'s mut ReplState<'a>,
    argv: &'s [&'s str],
    raw_tail: &'s str,
}

impl Args<'_, '_> {
    fn target(&self) -> &Target {
        &self.state.ctx.target
    }

    fn eval(&self, text: &str) -> Result<VirtAddr> {
        Expr::eval_with_radix(text, &self.state.ctx.target, self.state.radix)
    }

    fn addr(&self, index: usize) -> Result<VirtAddr> {
        match self.argv.get(index) {
            Some(text) => self.eval(text),
            None => Err(Error::DebugInfo(format!(
                "missing argument {} (an address expression)",
                index + 1
            ))),
        }
    }

    fn opt_addr(&self, index: usize) -> Result<Option<VirtAddr>> {
        self.argv.get(index).map(|text| self.eval(text)).transpose()
    }

    fn opt_value(&self, index: usize) -> Result<Option<u64>> {
        Ok(self.opt_addr(index)?.map(|value| value.0))
    }

    fn opt_u16_value(&self, index: usize, what: &str) -> Result<Option<u16>> {
        self.opt_value(index)?
            .map(|value| checked_u16(value, what))
            .transpose()
    }

    fn value(&self, index: usize) -> Result<u64> {
        self.addr(index).map(|value| value.0)
    }
}

fn checked_u16(value: u64, what: &str) -> Result<u16> {
    u16::try_from(value)
        .map_err(|_| Error::InvalidArgument(format!("{what} {value} is out of range")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_u16_arguments_reject_overflow_without_truncating() {
        assert_eq!(checked_u16(u16::MAX.into(), "processor").unwrap(), u16::MAX);
        assert!(matches!(
            checked_u16(0x1_0000, "IDT vector"),
            Err(Error::InvalidArgument(_))
        ));
    }
}
