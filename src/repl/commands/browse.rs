//! `browse`: the full-screen code and memory browser, which only Tern can
//! show ([`native::browser`]). F2 at the prompt opens it too.

use crate::error::Result;
use crate::repl::*;

repl_command! {
    cmd_browse;
    names: ["browse"],
    usage: "browse [<address>]",
    summary: "Browse code and memory in Tern.",
    details: "Opens a full-screen browser over the pane, at the address or else at the instruction pointer: code when the address is executable, else memory as pointers with the symbols they point into. The arrow keys and Page Up and Page Down move. Enter follows a branch, the memory an instruction addresses, or a pointer, and Backspace goes back. Tab shows the other of code and memory at the same address, g goes to an expression, b sets or clears a breakpoint, . goes to the instruction pointer, and Escape closes the browser. F2 at the prompt opens it at the instruction pointer. Only Tern can show it.",
    completion: Expression,
    style: ExpressionTail,
}

/// The host command F2 sends the REPL loop.
#[cfg(feature = "cli")]
pub const BROWSE_COMMAND: &str = "browse";

impl ReplState<'_> {
    fn cmd_browse(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = invocation.raw_tail.trim();
        self.open_browser((!expr.is_empty()).then_some(expr));
        Ok(())
    }

    /// Browse from `expr`, or from the instruction pointer, and print what
    /// the browser's commands printed once it closes.
    pub fn open_browser(&mut self, expr: Option<&str>) {
        #[cfg(feature = "cli")]
        {
            use crate::repl::native::browser::{self, Pane};

            if !native::active() {
                error!("browse needs Tern, Stencil's terminal");
                return;
            }
            let (address, pane) = match expr {
                Some(expr) => match self.eval_or_report(expr) {
                    Some(address) => (address.0, None),
                    None => return,
                },
                None => match self.ctx.target.builtin_variable_value("ip") {
                    Some(ip) => (ip, Some(Pane::Code)),
                    None => {
                        error!(
                            "no instruction pointer to browse from: give an address, or halt the target"
                        );
                        return;
                    }
                },
            };
            match browser::run(self, address, pane) {
                Ok(record) => {
                    for text in &record {
                        outln!("{text}");
                    }
                    if !record.is_empty() {
                        outln!();
                    }
                }
                Err(error) => error!("{error}"),
            }
        }
        #[cfg(not(feature = "cli"))]
        {
            let _ = expr;
            error!("browse needs Tern, Stencil's terminal");
        }
    }
}
