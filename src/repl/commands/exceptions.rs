use crate::dbg_backend::ContinueDisposition;
use crate::error::Result;
use crate::repl::*;
use crate::ui;

repl_command! {
    cmd_sxe;
    names: ["sxe"],
    usage: "sxe [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]>",
    summary: "Break when an exception occurs or a kernel module loads.",
    details: "-c runs commands at the stop, and -f sets an explicit final action: break, handled, or not handled. `sxe ld` stops when a kernel image loads, and `sxe ld:<module>` stops when that module loads. The module name is case-insensitive, the extension is optional, and you can use `*`/`?` globs. The stop occurs after ntoseye lists the module and arms its deferred breakpoints, and before its entry point runs. `-c` works with `sxe ld`, but `-f` does not apply to ld. `sxn ld` prints a `ModLoad:` line and continues, and `sxd ld` and `sxi ld` continue with no output. A named filter has precedence over bare `ld`. ntoseye does not support module unload (`ud`) filters.",
}

repl_command! {
    cmd_sxd;
    names: ["sxd"],
    usage: "sxd [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]>",
    summary: "Pass first-chance exceptions and break on second chance.",
    details: "-c runs commands at the stop, and -f sets an explicit final action: break, handled, or not handled. `sxd ld[:<module>]` lets the load continue with no output. See sxe.",
}

repl_command! {
    cmd_sxn;
    names: ["sxn"],
    usage: "sxn [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]>",
    summary: "Show a notification for exceptions and pass them without a break.",
    details: "-c runs commands at the stop, and -f sets an explicit final action: break, handled, or not handled. `sxn ld[:<module>]` prints a `ModLoad:` line at the load and continues. See sxe.",
}

repl_command! {
    cmd_sxi;
    names: ["sxi"],
    usage: "sxi [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]>",
    summary: "Pass exceptions without a break or a notification.",
    details: "-c runs commands at the stop, and -f sets an explicit final action: break, handled, or not handled. `sxi ld[:<module>]` lets the load continue with no output. See sxe.",
}

repl_command! {
    cmd_sx();
    names: ["sx", "sxl"],
    usage: "sx or sxl",
    summary: "List the configured exception policies and module-load filters.",
}

repl_command! {
    cmd_sxr();
    names: ["sxr"],
    usage: "sxr",
    summary: "Reset exception policies to the default break behavior, and clear module-load filters.",
}

repl_command! {
    cmd_lastevent();
    names: [".lastevent"],
    usage: ".lastevent",
    summary: "Show the most recent target event that ntoseye observed.",
}

/// Early feedback when a policy is set: refuse literal run-control commands
/// (by their registered [`RunEffect`], not a name list). Aliases resolve at
/// dispatch, where [`DispatchContext::ExceptionCommand`] enforces the same
/// rule after expansion.
fn validate_exception_command(command: &str) -> std::result::Result<(), String> {
    for item in split_command_list(command).map_err(|err| format!("{err:?}"))? {
        let Some(parsed) = parse_command(item).map_err(|err| format!("{err:?}"))? else {
            continue;
        };
        let is_run_control = parsed.name == "gc"
            || command_registry().get(parsed.name).is_some_and(|spec| {
                spec.run != RunEffect::None
                    || spec.run_state == Some(RunState::Running)
                    || spec.flow == Flow::Quit
            });
        if is_run_control {
            return Err(format!(
                "event command cannot contain run control '{}'; use -f break, -f gh, or -f gn for the final action",
                parsed.name
            ));
        }
    }
    Ok(())
}

/// What a module-load filter in `mode` does at a load.
fn module_load_label(mode: ExceptionPolicyMode) -> &'static str {
    match mode {
        ExceptionPolicyMode::Break => "break",
        ExceptionPolicyMode::Notify => "notify",
        ExceptionPolicyMode::SecondChance | ExceptionPolicyMode::Ignore => "ignore",
    }
}

impl ReplState<'_> {
    fn set_exception_policy(
        &mut self,
        invocation: CommandInvocation<'_>,
        mode: ExceptionPolicyMode,
    ) -> Result<()> {
        let mut code_arg = None;
        let mut command = None;
        let mut final_action = None;
        let mut index = 0;
        while index < invocation.argv.len() {
            match invocation.arg(index).expect("index is in bounds") {
                "-c" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("-c requires a quoted command string");
                        return Ok(());
                    };
                    command = Some(value.to_string());
                    index += 2;
                }
                "-f" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("-f requires break, gh, or gn");
                        return Ok(());
                    };
                    final_action = match parse_exception_final_action(value) {
                        Ok(action) => Some(action),
                        Err(err) => {
                            error!("{err}");
                            return Ok(());
                        }
                    };
                    index += 2;
                }
                value if code_arg.is_none() => {
                    code_arg = Some(value);
                    index += 1;
                }
                _ => {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
            }
        }
        let Some(value) = code_arg else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let code = match parse_event_filter(value) {
            Ok(EventFilter::Exception(code)) => code,
            Ok(EventFilter::ModuleLoad(module)) => {
                self.set_module_load_filter(module, mode, command, final_action);
                return Ok(());
            }
            Err(err) => {
                error!("{err}");
                return Ok(());
            }
        };
        if command.is_some() && final_action.is_none() {
            error!("-c requires an explicit final action: -f break, -f gh, or -f gn");
            return Ok(());
        }
        if let Some(event_command) = command.as_deref()
            && let Err(err) = validate_exception_command(event_command)
        {
            error!("{err}");
            return Ok(());
        }
        self.ctx
            .exception_policies
            .set_with_options(code, mode, command, final_action);
        let alias = exception_alias(code)
            .map(|alias| format!(" ({alias})"))
            .unwrap_or_default();
        let final_label = final_action
            .map(|action| format!(", final {}", action.label()))
            .unwrap_or_default();
        outln!(
            "{} {code:#010x}{alias}: {}{final_label}\n",
            mode.command(),
            mode.label()
        );
        Ok(())
    }

    fn set_module_load_filter(
        &mut self,
        module: Option<String>,
        mode: ExceptionPolicyMode,
        command: Option<String>,
        final_action: Option<ExceptionPolicyFinalAction>,
    ) {
        if final_action.is_some() {
            error!("-f does not apply to ld: a module load either stops (sxe) or continues");
            return;
        }
        if command.is_some() && mode != ExceptionPolicyMode::Break {
            error!("-c applies to ld only with sxe, where it runs at the stop");
            return;
        }
        if let Some(event_command) = command.as_deref()
            && let Err(err) = validate_exception_command(event_command)
        {
            error!("{err}");
            return;
        }
        if let Err(err) = self.ctx.set_module_load_filter(module, mode, command) {
            error!("{err}");
            return;
        }
        let policy = self
            .ctx
            .exception_policies
            .module_load_entries()
            .last()
            .expect("the filter was just set");
        outln!(
            "{} {}: {}\n",
            mode.command(),
            policy.event_name(),
            module_load_label(mode)
        );
    }

    fn cmd_sxe(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.set_exception_policy(invocation, ExceptionPolicyMode::Break)
    }

    fn cmd_sxd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.set_exception_policy(invocation, ExceptionPolicyMode::SecondChance)
    }

    fn cmd_sxn(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.set_exception_policy(invocation, ExceptionPolicyMode::Notify)
    }

    fn cmd_sxi(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.set_exception_policy(invocation, ExceptionPolicyMode::Ignore)
    }

    fn cmd_sx(&mut self) -> Result<()> {
        let entries: Vec<_> = self.ctx.exception_policies.entries().collect();
        let module_loads: Vec<_> = self.ctx.exception_policies.module_load_entries().collect();
        if entries.is_empty() && module_loads.is_empty() {
            outln!("No exception policies configured (ordinary exceptions break by default).\n");
            return Ok(());
        }
        if !module_loads.is_empty() {
            outln!("Module-load filters:");
            for policy in module_loads {
                let command = policy
                    .command
                    .as_deref()
                    .map(|command| format!("  -c {command:?}"))
                    .unwrap_or_default();
                outln!(
                    "  {:<24} {:<8} ({}){command}",
                    policy.event_name(),
                    module_load_label(policy.mode),
                    policy.mode.command()
                );
            }
            if entries.is_empty() {
                outln!();
                return Ok(());
            }
        }
        outln!("Exception policies:");
        for (code, policy) in entries {
            let alias = exception_alias(code)
                .map(|alias| format!(" {alias:<4}"))
                .unwrap_or_else(|| "     ".to_string());
            let final_action = policy
                .final_action
                .map(|action| format!(" -> {}", action.label()))
                .unwrap_or_default();
            let command = policy
                .command
                .as_deref()
                .map(|command| format!("  -c {command:?}"))
                .unwrap_or_default();
            outln!(
                "  {code:#010x}{alias}  {:<13} ({}){final_action}{command}",
                policy.mode.label(),
                policy.mode.command()
            );
        }
        outln!();
        Ok(())
    }

    fn cmd_sxr(&mut self) -> Result<()> {
        self.ctx.exception_policies.reset();
        outln!(
            "Exception policies reset; ordinary exceptions break by default and module loads do not stop.\n"
        );
        Ok(())
    }

    fn cmd_lastevent(&mut self) -> Result<()> {
        let Some(last) = &self.ctx.last_event else {
            outln!("No target event has been observed.\n");
            return Ok(());
        };
        let stop = &last.stop;
        outln!("Last event:");
        match stop.exception_code {
            Some(code) => {
                let alias = exception_alias(code)
                    .map(|alias| format!(" ({alias})"))
                    .unwrap_or_default();
                outln!("  code:        {code:#010x}{alias}");
            }
            None => outln!("  code:        unavailable"),
        }
        let chance = match stop.first_chance {
            Some(true) => "first chance",
            Some(false) => "second chance",
            None => "unavailable",
        };
        outln!("  chance:      {chance}");
        match stop.exception_address.or(stop.program_counter) {
            Some(address) => outln!("  address:     {}", ui::addr(address)),
            None => outln!("  address:     unavailable"),
        }
        let disposition = last
            .disposition
            .map(ContinueDisposition::label)
            .unwrap_or("not yet continued");
        outln!("  disposition: {disposition}\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_commands_reject_embedded_run_control() {
        assert!(validate_exception_command("registers; k").is_ok());
        assert!(validate_exception_command("registers; gn").is_err());
        assert!(validate_exception_command("gc").is_err());
    }
}
