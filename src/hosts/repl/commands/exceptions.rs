//! Exception stop policies and module load and unload filters (`sx*`), and
//! the last target event (`.lastevent`).

use ntoseye_macros::{command, grammar};

use crate::backend::dbg_backend::{ContinueDisposition, LastEvent, ModuleEvent};
use crate::base::error::{Error, Result};
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::session::Session;

/// An `sx*` line's words, checked in order as WinDbg reads them: `-c
/// <commands>`, `-f <break|gh|gn>`, and one event, in any order. Returns
/// the event; `-c` and `-f` are left for [`event_command`] and
/// [`final_action`], which the check made sure are well formed.
#[grammar(
    usage = "[-c <commands>] [-f <break|gh|gn>] <exception-code|alias|ld[:<module>]|ud[:<module>]>",
    complete = None
)]
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
#[grammar(usage = "")]
fn event_command(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    Ok(option_value(cursor, "-c"))
}

/// `-f <break|gh|gn>`.
#[grammar(usage = "")]
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
// The forms are SDK-only: the line's grammar (`-c`, `-f` and the event in
// any order, `ld:<module>`) has no form words, so `sxe` parses it and calls
// the operation the event names.
#[command(
    names = ["sxe"],
    category = "breakpoints and events",
    kind = Action,
    forms = [set_exception_policy, set_module_event],
)]
fn sxe(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    set_event_policy(
        session,
        code,
        ExceptionPolicyMode::Break,
        command,
        disposition,
    )
}

/// What an `sx*` command set: an exception's policy, or a module load or
/// unload filter.
enum EventPolicy {
    Exception(ExceptionPolicy),
    Module(ModuleEventPolicy),
}

/// An `sx*` line's operation: the policy of the exception, or the filter of
/// the module event (`ld[:<module>]`, `ud[:<module>]`), that `code` names.
fn set_event_policy(
    session: &mut Session,
    code: EventName,
    mode: ExceptionPolicyMode,
    command: Option<String>,
    disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    match code.resolve().map_err(Error::DebugInfo)? {
        EventFilter::Exception(code) => {
            set_exception(session, code, mode, command, disposition).map(EventPolicy::Exception)
        }
        EventFilter::Module(event, module) => {
            if disposition.is_some() {
                return Err(Error::DebugInfo(format!(
                    "-f does not apply to {}: a module event either stops (sxe) or continues",
                    event.as_str()
                )));
            }
            set_module_filter(session, event, module, mode, command).map(EventPolicy::Module)
        }
    }
}

fn set_exception(
    session: &mut Session,
    code: u32,
    mode: ExceptionPolicyMode,
    command: Option<String>,
    disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<ExceptionPolicy> {
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
    Ok(policy.clone())
}

fn set_module_filter(
    session: &mut Session,
    event: ModuleEvent,
    module: Option<String>,
    mode: ExceptionPolicyMode,
    command: Option<String>,
) -> Result<ModuleEventPolicy> {
    if command.is_some() && mode != ExceptionPolicyMode::Break {
        return Err(Error::DebugInfo(format!(
            "-c applies to {} only with sxe, where it runs at the stop",
            event.as_str()
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
    Ok(policy.clone())
}

/// Set how the debugger handles an exception, by NTSTATUS code or WinDbg
/// alias (`av`, `bpe`, ...), and return its policy.
///
/// `mode` is `break` (the default), `second_chance`, `notify` or `ignore`.
/// `command` runs at the stop, which needs an explicit `disposition`: break,
/// or continue the exception as handled or not handled. For a module load
/// or unload filter, use `set_module_event`.
#[command(form_of = sxe, python = Exceptions, python_name = "set")]
fn set_exception_policy(
    session: &mut Session,
    code: EventName,
    mode: Option<ExceptionPolicyMode>,
    command: Option<String>,
    disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<ExceptionPolicy> {
    let mode = mode.unwrap_or(ExceptionPolicyMode::Break);
    match code.resolve().map_err(Error::DebugInfo)? {
        EventFilter::Exception(code) => set_exception(session, code, mode, command, disposition),
        EventFilter::Module(event, _) => Err(Error::InvalidArgument(format!(
            "{} is a module event, not an exception: use set_module_event(\"{}\", ...)",
            event.as_str(),
            event.as_str()
        ))),
    }
}

/// Set a filter for a kernel module load (`ld`) or unload (`ud`), and return
/// it.
///
/// `module` limits it to one image (a case-insensitive name; the extension
/// is optional, and `*`/`?` globs match); without it, the filter applies to
/// every image. `mode` is `break` (the default; a load stops after ntoseye
/// lists the module and arms its deferred breakpoints, an unload while the
/// image is still listed), `notify` (a `ModLoad:` or `Unload module` notice,
/// then the target continues), or `second_chance` or `ignore` (it
/// continues). `command` runs at the stop, so only with `break`. A named
/// filter has precedence over a bare one.
#[command(form_of = sxe, python = Exceptions)]
fn set_module_event(
    session: &mut Session,
    event: ModuleEvent,
    #[arg(positional)] module: Option<String>,
    mode: Option<ExceptionPolicyMode>,
    command: Option<String>,
) -> Result<ModuleEventPolicy> {
    let module = match module.as_deref().map(str::trim) {
        Some("") => {
            return Err(Error::InvalidArgument(format!(
                "an empty module name names no module (omit it to filter every {})",
                event.as_str()
            )));
        }
        trimmed => trimmed.map(str::to_string),
    };
    let mode = mode.unwrap_or(ExceptionPolicyMode::Break);
    set_module_filter(session, event, module, mode, command)
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
                    "{} {:#010x}{alias}: {}{final_label}",
                    policy.mode.command(),
                    policy.code,
                    policy.mode.label()
                );
            }
            EventPolicy::Module(policy) => outln!(
                "{} {}: {}",
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
)]
fn set_second_chance(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    set_event_policy(
        session,
        code,
        ExceptionPolicyMode::SecondChance,
        command,
        disposition,
    )
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
)]
fn set_notify(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    set_event_policy(
        session,
        code,
        ExceptionPolicyMode::Notify,
        command,
        disposition,
    )
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
)]
fn set_ignore(
    session: &mut Session,
    #[arg(parse = event_name)] code: EventName,
    #[arg(parse = event_command)] command: Option<String>,
    #[arg(parse = final_action)] disposition: Option<ExceptionPolicyFinalAction>,
) -> Result<EventPolicy> {
    set_event_policy(
        session,
        code,
        ExceptionPolicyMode::Ignore,
        command,
        disposition,
    )
}

/// List the configured exception policies and module load and unload filters.
#[command(
    names = ["sx", "sxl"],
    category = "breakpoints and events",
    kind = Query,
    python = none,
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
            outln!(
                "{}",
                ui::muted("no exception policies configured; ordinary exceptions break by default")
            );
            return;
        }
        if !self.module_events.is_empty() {
            outln!("module load and unload filters:");
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
                return;
            }
            outln!();
        }
        outln!("exception policies:");
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
    }
}

/// The exception policies were reset (`sxr`).
pub struct PoliciesReset;

/// Reset exception policies to the default break behavior, and clear module load and unload filters.
#[command(
    names = ["sxr"],
    category = "breakpoints and events",
    kind = Action,
    forms = [reset],
)]
fn reset_event_policies(session: &mut Session) -> Result<PoliciesReset> {
    reset(session)?;
    Ok(PoliciesReset)
}

/// Remove all configured policies and module load and unload filters, so
/// ordinary exceptions break by default and module loads and unloads do not
/// stop (`sxr`).
#[command(form_of = reset_event_policies, python = Exceptions)]
fn reset(session: &mut Session) -> Result<()> {
    session.exception_policies.reset();
    Ok(())
}

impl Render for PoliciesReset {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "exception policies reset; ordinary exceptions break by default and module loads and unloads do not stop"
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
                outln!("{}", ui::muted("no target event has been observed"));
                return;
            }
            LastEventReport::Minidump {
                code,
                address,
                thread,
            } => {
                outln!("last event (the minidump's exception record)");
                outln!("  code         {code:#010x}{}", alias(*code));
                outln!("  chance       -");
                outln!("  address      {}", ui::addr(*address));
                outln!("  thread       {thread}");
                return;
            }
            LastEventReport::Event(last) => last,
        };
        let stop = &last.stop;
        outln!("last event");
        match stop.exception_code {
            Some(code) => outln!("  code         {code:#010x}{}", alias(code)),
            None => outln!("  code         -"),
        }
        let chance = match stop.first_chance {
            Some(true) => "first chance",
            Some(false) => "second chance",
            None => "-",
        };
        outln!("  chance       {chance}");
        match stop.exception_address.or(stop.program_counter) {
            Some(address) => outln!("  address      {}", ui::addr(address)),
            None => outln!("  address      -"),
        }
        let disposition = last
            .disposition
            .map(ContinueDisposition::label)
            .unwrap_or("not yet continued");
        outln!("  disposition  {disposition}");
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
