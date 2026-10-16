//! Exception stop policies and module load and unload filters (`sx*`), and
//! the last target event (`.lastevent`).

use ntoseye_macros::command;

use crate::dbg_backend::{ContinueDisposition, LastEvent};
use crate::error::{Error, Result};
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::ui;

/// An `sx*` line's words, checked in order as WinDbg reads them: `-c
/// <commands>`, `-f <break|gh|gn>`, and one event, in any order. Returns
/// the event; `-c` and `-f` are left for [`event_command`] and
/// [`final_action`], which the check made sure are well formed.
fn event_name(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<EventName, ArgError> {
    let words: Vec<String> = cursor.words().map(str::to_string).collect();
    let mut event = None;
    let mut index = 0;
    while index < words.len() {
        match words[index].as_str() {
            "-c" => {
                if words.get(index + 1).is_none() {
                    return Err(ArgError::Message(
                        "-c requires a quoted command string".to_string(),
                    ));
                }
                index += 2;
            }
            "-f" => {
                let Some(value) = words.get(index + 1) else {
                    return Err(ArgError::Message(
                        "-f requires break, gh, or gn".to_string(),
                    ));
                };
                parse_exception_final_action(value).map_err(ArgError::Message)?;
                index += 2;
            }
            _ if event.is_none() => {
                event = Some(index);
                index += 1;
            }
            _ => return Err(ArgError::Missing),
        }
    }
    let index = event.ok_or(ArgError::Missing)?;
    let word = cursor.word_at(index).ok_or(ArgError::Missing)?;
    Ok(EventName::Text(word.into_owned()))
}

/// The value after `option` (`-c`, `-f`), taken with it.
fn option_value(cursor: &mut ArgCursor<'_>, option: &str) -> Option<String> {
    let index = cursor.words().position(|word| word == option)?;
    cursor.word_at(index);
    cursor.word_at(index).map(|value| value.into_owned())
}

/// `-c <commands>`.
fn event_command(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    Ok(option_value(cursor, "-c"))
}

/// `-f <break|gh|gn>`.
fn final_action(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<ExceptionPolicyFinalAction>, ArgError> {
    option_value(cursor, "-f")
        .map(|value| parse_exception_final_action(&value).map_err(ArgError::Message))
        .transpose()
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
                spec.effects.run != RunEffect::None
                    || spec.effects.state == RunState::Running
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

/// What a module load or unload filter in `mode` does at the event.
fn module_event_label(mode: ExceptionPolicyMode) -> &'static str {
    match mode {
        ExceptionPolicyMode::Break => "break",
        ExceptionPolicyMode::Notify => "notify",
        ExceptionPolicyMode::SecondChance | ExceptionPolicyMode::Ignore => "ignore",
    }
}

/// Break when an exception occurs or a kernel module loads or unloads.
///
/// -c runs commands at the stop, and -f sets an explicit final action:
/// break, handled, or not handled. `sxe ld` stops when a kernel image loads,
/// and `sxe ld:<module>` stops when that module loads. The module name is
/// case-insensitive, the extension is optional, and you can use `*`/`?`
/// globs. The stop occurs after ntoseye lists the module and arms its
/// deferred breakpoints, and before its entry point runs. `sxe ud` and `sxe
/// ud:<module>` stop when a kernel image unloads, after its driver's unload
/// routine has run and while the image is still in the module list. `-c`
/// works with `sxe ld` and `sxe ud`, but `-f` does not apply to them. `sxn
/// ld` prints a `ModLoad:` line and continues, `sxn ud` prints an `Unload
/// module` line and continues, and `sxd` and `sxi` let the load or unload
/// continue with no output. A named filter has precedence over bare `ld` or
/// `ud`.
#[command(
    names = ["sxe"],
    category = "breakpoints and events",
    kind = Action,
    python = Exceptions,
    python_name = "set",
    usage = "sxe [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]|ud[:<module>]>",
    completion = None
)]
fn set_event_policy(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(sdk, default = None)] mode: Option<ExceptionPolicyMode>,
    #[arg(parse = event_command, keyword, default = None)] command: Option<String>,
    #[arg(parse = final_action, keyword, default = None)] disposition: Option<
        ExceptionPolicyFinalAction,
    >,
) -> Result<EventPolicy> {
    let mode = mode.unwrap_or(ExceptionPolicyMode::Break);
    let filter = code.resolve().map_err(Error::DebugInfo)?;
    let code = match filter {
        EventFilter::Exception(code) => code,
        EventFilter::Module(event, module) => {
            let name = event.filter_name();
            if disposition.is_some() {
                return Err(Error::DebugInfo(format!(
                    "-f does not apply to {name}: a module event either stops (sxe) or continues"
                )));
            }
            if command.is_some() && mode != ExceptionPolicyMode::Break {
                return Err(Error::DebugInfo(format!(
                    "-c applies to {name} only with sxe, where it runs at the stop"
                )));
            }
            if let Some(event_command) = command.as_deref() {
                validate_exception_command(event_command).map_err(Error::DebugInfo)?;
            }
            session.set_module_event_filter(event, module, mode, command)?;
            let policy = session
                .exception_policies
                .module_event_entries()
                .last()
                .expect("the filter was just set");
            return Ok(EventPolicy::Module(policy.clone()));
        }
    };
    if command.is_some() && disposition.is_none() {
        return Err(Error::DebugInfo(
            "-c requires an explicit final action: -f break, -f gh, or -f gn".to_string(),
        ));
    }
    if let Some(event_command) = command.as_deref() {
        validate_exception_command(event_command).map_err(Error::DebugInfo)?;
    }
    session
        .exception_policies
        .set_with_options(code, mode, command, disposition);
    let policy = session
        .exception_policies
        .entries()
        .find(|policy| policy.code == code)
        .expect("the policy was just set");
    Ok(EventPolicy::Exception(policy.clone()))
}

impl Render for EventPolicy {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            EventPolicy::Exception(policy) => {
                let alias = policy
                    .alias()
                    .map(|alias| format!(" ({alias})"))
                    .unwrap_or_default();
                let final_label = policy
                    .final_action
                    .map(|action| format!(", final {}", action.label()))
                    .unwrap_or_default();
                outln!(
                    "{} {:#010x}{alias}: {}{final_label}\n",
                    policy.mode.command(),
                    policy.code,
                    policy.mode.label()
                );
            }
            EventPolicy::Module(policy) => outln!(
                "{} {}: {}\n",
                policy.mode.command(),
                policy.event_name(),
                module_event_label(policy.mode)
            ),
        }
    }
}

/// Pass first-chance exceptions and break on second chance.
///
/// -c runs commands at the stop, and -f sets an explicit final action:
/// break, handled, or not handled. `sxd ld[:<module>]` and `sxd
/// ud[:<module>]` let the load or unload continue with no output. See sxe.
#[command(
    names = ["sxd"],
    category = "breakpoints and events",
    kind = Action,
    python = none,
    usage = "sxd [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]|ud[:<module>]>",
    completion = None
)]
fn set_second_chance(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    let mode = Some(ExceptionPolicyMode::SecondChance);
    set_event_policy(session, code, mode, command, disposition)
}

/// Show a notification for exceptions and pass them without a break.
///
/// -c runs commands at the stop, and -f sets an explicit final action:
/// break, handled, or not handled. `sxn ld[:<module>]` prints a `ModLoad:`
/// line at the load and continues, and `sxn ud[:<module>]` prints an `Unload
/// module` line at the unload and continues. See sxe.
#[command(
    names = ["sxn"],
    category = "breakpoints and events",
    kind = Action,
    python = none,
    usage = "sxn [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]|ud[:<module>]>",
    completion = None
)]
fn set_notify(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    let mode = Some(ExceptionPolicyMode::Notify);
    set_event_policy(session, code, mode, command, disposition)
}

/// Pass exceptions without a break or a notification.
///
/// -c runs commands at the stop, and -f sets an explicit final action:
/// break, handled, or not handled. `sxi ld[:<module>]` and `sxi
/// ud[:<module>]` let the load or unload continue with no output. See sxe.
#[command(
    names = ["sxi"],
    category = "breakpoints and events",
    kind = Action,
    python = none,
    usage = "sxi [-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]|ud[:<module>]>",
    completion = None
)]
fn set_ignore(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    let mode = Some(ExceptionPolicyMode::Ignore);
    set_event_policy(session, code, mode, command, disposition)
}

/// List the configured exception policies and module load and unload filters.
#[command(
    names = ["sx", "sxl"],
    category = "breakpoints and events",
    kind = Query,
    python = none,
    usage = "sx or sxl"
)]
fn event_policies(session: &Session) -> Result<EventPolicies> {
    let policies = &session.exception_policies;
    Ok(EventPolicies {
        exceptions: policies.entries().cloned().collect(),
        module_events: policies.module_event_entries().cloned().collect(),
    })
}

impl Render for EventPolicies {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.exceptions.is_empty() && self.module_events.is_empty() {
            outln!("No exception policies configured (ordinary exceptions break by default).\n");
            return;
        }
        if !self.module_events.is_empty() {
            outln!("Module load and unload filters:");
            for policy in &self.module_events {
                let command = policy
                    .command
                    .as_deref()
                    .map(|command| format!("  -c {command:?}"))
                    .unwrap_or_default();
                outln!(
                    "  {:<24} {:<8} ({}){command}",
                    policy.event_name(),
                    module_event_label(policy.mode),
                    policy.mode.command()
                );
            }
            if self.exceptions.is_empty() {
                outln!();
                return;
            }
        }
        outln!("Exception policies:");
        for policy in &self.exceptions {
            let alias = policy
                .alias()
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
                "  {:#010x}{alias}  {:<13} ({}){final_action}{command}",
                policy.code,
                policy.mode.label(),
                policy.mode.command()
            );
        }
        outln!();
    }
}

/// The exception policies were reset (`sxr`).
pub struct PoliciesReset;

/// Reset exception policies to the default break behavior, and clear module load and unload filters.
#[command(
    names = ["sxr"],
    category = "breakpoints and events",
    kind = Action,
    python = none,
    usage = "sxr"
)]
fn reset_event_policies(session: &mut Session) -> Result<PoliciesReset> {
    session.exception_policies.reset();
    Ok(PoliciesReset)
}

impl Render for PoliciesReset {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "Exception policies reset; ordinary exceptions break by default and module loads and unloads do not stop.\n"
        );
    }
}

/// The most recent target event: the stop the debugger last saw, or a
/// minidump's exception record.
pub enum LastEventReport {
    Event(LastEvent),
    /// A minidump runs nothing; its event is the exception it was written
    /// for, which does not record the chance.
    Minidump {
        code: u32,
        address: u64,
        thread: String,
    },
    None,
}

/// Show the most recent target event that ntoseye observed.
#[command(
    names = [".lastevent"],
    category = "target control",
    kind = Query,
    python = none,
    usage = ".lastevent"
)]
fn last_event(session: &Session) -> Result<LastEventReport> {
    if let Some(last) = &session.last_event {
        return Ok(LastEventReport::Event(last.clone()));
    }
    Ok(session
        .target
        .user_dump_info()
        .and_then(|info| {
            info.exception
                .as_ref()
                .map(|exception| LastEventReport::Minidump {
                    code: exception.code,
                    address: exception.address,
                    thread: info.backend_thread_id(exception.thread_id),
                })
        })
        .unwrap_or(LastEventReport::None))
}

impl Render for LastEventReport {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let alias = |code: u32| {
            exception_alias(code)
                .map(|alias| format!(" ({alias})"))
                .unwrap_or_default()
        };
        let last = match self {
            LastEventReport::None => {
                outln!("No target event has been observed.\n");
                return;
            }
            LastEventReport::Minidump {
                code,
                address,
                thread,
            } => {
                outln!("Last event (the minidump's exception record):");
                outln!("  code:        {code:#010x}{}", alias(*code));
                outln!("  chance:      unavailable");
                outln!("  address:     {}", ui::addr(*address));
                outln!("  thread:      {thread}\n");
                return;
            }
            LastEventReport::Event(last) => last,
        };
        let stop = &last.stop;
        outln!("Last event:");
        match stop.exception_code {
            Some(code) => outln!("  code:        {code:#010x}{}", alias(code)),
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
