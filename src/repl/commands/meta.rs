use crate::error::Result;
use crate::expr::NumberRadix;
#[cfg(feature = "python")]
use crate::python::embed;

use crate::repl::*;

repl_command! {
    cmd_reload_scripts();
    names: ["reload-scripts"],
    usage: "reload-scripts",
    summary: "Reload custom commands and aliases.",
}

repl_command! {
    cmd_radix;
    names: ["n"],
    usage: "n [8|10|16]",
    summary: "Display or set the default numeric radix for REPL expressions.",
}

repl_command! {
    names: ["quit", "q"],
    usage: "quit",
    summary: "Exit the application.",
    flow: Quit,
}

impl ReplState<'_> {
    fn cmd_reload_scripts(&mut self) -> Result<()> {
        #[cfg(feature = "python")]
        {
            let py_report = embed::load_commands_dir();
            embed::print_script_load_report(&py_report);
            *self.caches.user_commands.write().unwrap() = initial_user_commands();
        }
        let alias_report = self.reload_aliases();
        print_alias_load_report(&alias_report);
        Ok(())
    }

    fn cmd_radix(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(value) = invocation.arg(0) {
            self.radix = match value {
                "8" => NumberRadix::Octal,
                "10" => NumberRadix::Decimal,
                "16" => NumberRadix::Hexadecimal,
                _ => {
                    error!("invalid radix '{value}' (use 8, 10, or 16)");
                    return Ok(());
                }
            };
        }

        let name = match self.radix {
            NumberRadix::Octal => "octal",
            NumberRadix::Decimal => "decimal",
            NumberRadix::Hexadecimal => "hexadecimal",
        };
        outln!("radix {} ({name})\n", self.radix.value());
        Ok(())
    }

    pub fn cmd_user(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        #[cfg(feature = "python")]
        if embed::has_command(invocation.name) {
            let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
            if let Err(e) = embed::dispatch(invocation.name, &args, self.ctx) {
                error!("{}: {}", invocation.name, e);
            }
            return Ok(());
        }

        outln!(
            "unknown command: '{}' (try pressing tab to see available commands)\n",
            invocation.name
        );

        Ok(())
    }
}
