//! `browse`: the full-screen code and memory browser, which only Tern can
//! show ([`native::browser`]). F2 at the prompt opens it too.

use crate::error::Result;
use crate::repl::*;

repl_command! {
    cmd_browse;
    names: ["browse"],
    usage: "browse [<address>]",
    summary: "Browse code and memory in Tern.",
    details: "Opens a full-screen browser over the pane, at the address or else at the instruction pointer: code when the address is executable, with the registers and the stack beside it, else memory as bytes with an inspector of the values at the cursor. The arrow keys and Shift+Up and Shift+Down move. Enter follows a branch, the memory an instruction addresses, or a pointer, and Backspace goes back. Tab shows the other of code and memory at the same address, g goes to an expression, / finds, b sets or clears a breakpoint or a write watchpoint, . goes to the instruction pointer, and Escape closes the browser. F10, F11, Shift+F11 and F5 step and run the target as p, t, gu and g do, F7 runs to the cursor, and Escape breaks in; what a run changed is highlighted. In code, [ and ] show the caller's frame and back, and r hides the registers and stack. In memory, t reads the memory as a type, as dt does: its fields open in place with the arrow keys, and Enter follows a pointer as its type or a list link to the next record. F2 at the prompt opens the browser at the instruction pointer. Only Tern can show it.",
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
                    for text in &record.lines {
                        outln!("{text}");
                    }
                    if !record.lines.is_empty() {
                        outln!();
                    }
                    // Where the runs from the browser left the target, as
                    // the prompt shows a stop.
                    if record.ran && !self.ctx.backend.is_running() {
                        print_break_context_at(self.ctx, None, None);
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
