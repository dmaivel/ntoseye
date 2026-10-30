//! Client breakpoint sets (source, function, instruction, data), each
//! replaced in one halt, and verification changes reported as they happen.

use std::mem::take;
use std::result;

use serde_json::{Value, json};

use crate::backend::dbg_backend::{ModuleEvent, WatchpointAccess};
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::{BreakpointConfig, BreakpointInfo};
use crate::session::Session;
use crate::session::exception_policy::ExceptionPolicyMode;

use super::{Handled, Server, arg_i64, arg_str, file_stem_of, parse_address};

impl Server {
    /// Reconcile symbolic breakpoints and report verification changes.
    ///
    /// Compare per-id state at every stop: module-load notifications may have
    /// already reconciled the breakpoint and consumed the module-change signal.
    pub(super) fn reconcile_breakpoints(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        session.refresh_modules_on_stop();
        let groups: Vec<Vec<Owned>> = self.owned_groups().cloned().collect();
        for group in groups {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            let mut changed = false;
            let mut first = None;
            for owned in &group {
                let Some(breakpoint) = session.breakpoints.live(owned.id, owned.serial) else {
                    self.verified.remove(&owned.id);
                    continue;
                };
                let state = BreakpointState::from(breakpoint);
                changed |= self.verified.insert(owned.id, state) != Some(state);
                first.get_or_insert(breakpoint);
            }
            let Some(breakpoint) = first.filter(|_| changed) else {
                continue;
            };
            // One event per client breakpoint, under the id the client holds.
            let mut breakpoint = breakpoint_json(breakpoint, group.len());
            breakpoint["id"] = json!(group[0].id);
            self.send_event(
                "breakpoint",
                json!({"reason": "changed", "breakpoint": breakpoint}),
            );
        }
    }

    /// Every client breakpoint, as the session breakpoints it installed.
    fn owned_groups(&self) -> impl Iterator<Item = &Vec<Owned>> {
        self.source_breakpoints
            .values()
            .flatten()
            .chain(&self.function_breakpoints)
            .chain(&self.instruction_breakpoints)
            .chain(&self.data_breakpoints)
    }

    /// The id the client knows a session breakpoint by, if one of its own
    /// breakpoints installed it.
    pub(super) fn client_breakpoint_id(&self, id: u32, serial: u64) -> Option<u32> {
        self.owned_groups()
            .find(|group| group.contains(&Owned { id, serial }))
            .map(|group| group[0].id)
    }

    pub(super) fn on_set_breakpoints(&mut self, args: &Value) -> Handled {
        let source = args.get("source").cloned().unwrap_or_else(|| json!({}));
        let key = arg_str(&source, "path")
            .or_else(|| arg_str(&source, "name"))
            .ok_or_else(|| "source breakpoints need a path or name".to_string())?;
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let lines: Vec<Option<i64>> = requested
            .iter()
            .map(|entry| arg_i64(entry, "line"))
            .collect();
        let plan = requested
            .iter()
            .zip(&lines)
            .map(|(entry, line)| {
                let line = line.ok_or_else(|| "breakpoint without a line".to_string())?;
                let config = breakpoint_config(entry)?;
                let spec = self.source_spec(&key, self.to_source_line(line));
                Ok(Install::Source(spec, config))
            })
            .collect();
        let previous = self
            .source_breakpoints
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let (results, kept) = self.install_breakpoints(&previous, plan)?;
        let mut installed = retain_kept(previous, &kept);
        installed.reserve(results.len());
        let mut response = Vec::with_capacity(results.len());
        for (result, line) in results.into_iter().zip(lines) {
            match result {
                Ok(ids) => {
                    response.push(self.breakpoint_value(&ids, line));
                    installed.push(ids);
                }
                Err(message) => response.push(refused_breakpoint(message, line)),
            }
        }
        self.source_breakpoints.insert(key, installed);
        Ok(Some(json!({"breakpoints": response})))
    }

    /// Choose the `file:line` identity ntoseye should resolve. The client's
    /// absolute path is tried first (it matches when `.srcpath` maps the PDB
    /// path onto it); otherwise the basename, which matches any recorded file
    /// with that name.
    fn source_spec(&mut self, path: &str, line: u32) -> String {
        let matched_full = self
            .session
            .as_ref()
            .is_some_and(|session| !session.target.source_addresses(path, line).is_empty());
        if matched_full {
            return format!("{path}:{line}");
        }
        let base = file_stem_of(path);
        format!("{base}:{line}")
    }

    pub(super) fn on_set_function_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let name = arg_str(entry, "name")
                    .ok_or_else(|| "breakpoint without a name".to_string())?;
                // Skip the prologue so arguments occupy their PDB locations.
                // Console `bu` still breaks at the symbol address.
                let config = BreakpointConfig {
                    skip_prologue: true,
                    ..breakpoint_config(entry)?
                };
                Ok(Install::Symbol(name, config))
            })
            .collect();
        self.replace_owned_set(OwnedSet::Function, plan)
    }

    pub(super) fn on_set_instruction_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let address = arg_str(entry, "instructionReference")
                    .ok_or_else(|| "breakpoint without an instructionReference".to_string())
                    .and_then(|reference| parse_address(&reference))?
                    .wrapping_add_signed(arg_i64(entry, "offset").unwrap_or(0));
                let config = breakpoint_config(entry)?;
                Ok(Install::Address(address, config))
            })
            .collect();
        self.replace_owned_set(OwnedSet::Instruction, plan)
    }

    fn owned_set(&mut self, set: OwnedSet) -> &mut Vec<Vec<Owned>> {
        match set {
            OwnedSet::Function => &mut self.function_breakpoints,
            OwnedSet::Instruction => &mut self.instruction_breakpoints,
            OwnedSet::Data => &mut self.data_breakpoints,
        }
    }

    /// Answer a `set*Breakpoints` request for a set without source lines.
    pub(super) fn replace_owned_set(
        &mut self,
        set: OwnedSet,
        plan: Vec<result::Result<Install, String>>,
    ) -> Handled {
        let previous = take(self.owned_set(set));
        let (results, kept) = match self.install_breakpoints(&previous, plan) {
            Ok(installed) => installed,
            Err(message) => {
                *self.owned_set(set) = previous;
                return Err(message);
            }
        };
        *self.owned_set(set) = retain_kept(previous, &kept);
        let mut response = Vec::with_capacity(results.len());
        for result in results {
            match result {
                Ok(ids) => {
                    response.push(self.breakpoint_value(&ids, None));
                    self.owned_set(set).push(ids);
                }
                Err(message) => response.push(refused_breakpoint(message, None)),
            }
        }
        Ok(Some(json!({"breakpoints": response})))
    }

    /// Replace one client-owned breakpoint set in a single halt/resume round
    /// trip: remove what the client last sent, install what it sends now.
    /// Results align with `plan`; a slot refused before the target was
    /// touched passes through.
    ///
    /// `Err` means the target could not be halted and nothing changed. A
    /// failure to resume afterwards is reported to the console instead: the
    /// edits stand, and the next service tick surfaces the halt. So is a
    /// breakpoint that could not be removed: it is still installed, so it is
    /// returned to stay owned, and its hits stay recognised.
    fn install_breakpoints(
        &mut self,
        remove: &[Vec<Owned>],
        mut plan: Vec<result::Result<Install, String>>,
    ) -> result::Result<Installed, String> {
        let session = self.session()?;
        let mut results = Vec::with_capacity(plan.len());
        let mut kept = Vec::new();
        let mut failures = Vec::new();
        let mut edited = false;
        let outcome = session.with_target_halted(|session| {
            edited = true;
            for &owned in remove.iter().flatten() {
                // Gone already (cleared from the console), or the id now
                // names a breakpoint the client does not own.
                if session.breakpoints.live(owned.id, owned.serial).is_none() {
                    continue;
                }
                match session.remove_breakpoint(owned.id) {
                    Ok(()) | Err(Error::BPNotFound(_)) => {}
                    Err(error) => {
                        failures.push(format!("#{}: {error}", owned.id));
                        kept.push(owned);
                    }
                }
            }
            results.extend(plan.drain(..).map(|slot| {
                let ids = slot.and_then(|install| {
                    install.apply(session).map_err(|error| error.to_string())
                })?;
                Ok(ids
                    .into_iter()
                    .filter_map(|id| {
                        let serial = session.breakpoints.listed(id)?.serial;
                        Some(Owned { id, serial })
                    })
                    .collect())
            }));
            Ok(())
        });
        match outcome {
            Ok(()) => {}
            Err(error) if !edited => {
                return Err(format!(
                    "breakpoints unchanged; the target could not be halted: {error}"
                ));
            }
            Err(error) => self.emit_output(
                "important",
                format!("ntoseye: breakpoints changed but the target did not resume: {error}\n"),
            ),
        }
        if !failures.is_empty() {
            self.emit_output(
                "important",
                format!(
                    "ntoseye: could not remove breakpoints, which stay installed: {}\n",
                    failures.join("; ")
                ),
            );
        }
        for owned in remove.iter().flatten() {
            if !kept.contains(owned) {
                self.verified.remove(&owned.id);
            }
        }
        Ok((results, kept))
    }

    /// Report one installed breakpoint: verified once an address is resolved,
    /// unverified (with the reason) while it stays deferred.
    fn breakpoint_value(&mut self, ids: &[Owned], line: Option<i64>) -> Value {
        let Some(session) = self.session.as_ref() else {
            return json!({"verified": false, "message": "no target attached"});
        };
        let first = ids.first().and_then(|owned| session.breakpoint(owned.id));
        // One client breakpoint can install several ids (a source line with
        // more than one address). `reconcile_breakpoints` walks all of them, so
        // all of them have to be seeded here or the ids the client never saw
        // each report a spurious change at the next stop.
        let states: Vec<(u32, BreakpointState)> = ids
            .iter()
            .filter_map(|owned| {
                session
                    .breakpoint(owned.id)
                    .map(|breakpoint| (owned.id, BreakpointState::from(breakpoint)))
            })
            .collect();
        for (id, state) in states {
            self.verified.insert(id, state);
        }
        let mut value = match first {
            Some(breakpoint) => breakpoint_json(breakpoint, ids.len()),
            None => json!({"verified": false, "message": "breakpoint was not installed"}),
        };
        if let Some(line) = line {
            value["line"] = json!(line);
        }
        value
    }

    /// Apply the client's exception filters as `sx` policy: a checked
    /// exception filter breaks at the first chance (`sxe`), an unchecked one
    /// only at the second (`sxd`); a checked module event stops at each load
    /// or unload (`sxe ld`), an unchecked one does not (`sxi ld`).
    /// Conditions on filters are refused.
    pub(super) fn on_set_exception_breakpoints(&mut self, args: &Value) -> Handled {
        for field in ["filterOptions", "exceptionOptions"] {
            let requested = args
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|entries| !entries.is_empty());
            if requested {
                return Err(format!(
                    "exception filters take no conditions; '{field}' cannot be honored. Use the \
                     console's `sx` commands, such as `sxe -c \"<command>\" av`"
                ));
            }
        }
        let checked: Vec<&str> = args
            .get("filters")
            .and_then(Value::as_array)
            .map(|filters| filters.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(unknown) = checked
            .iter()
            .find(|name| !EXCEPTION_FILTERS.iter().any(|filter| filter.name == **name))
        {
            return Err(format!("unknown exception filter '{unknown}'"));
        }
        let session = self.session()?;
        let mut breakpoints = Vec::new();
        for filter in EXCEPTION_FILTERS {
            let on = checked.contains(&filter.name);
            match filter.event {
                FilterEvent::Exception(code) => session.exception_policies.set(
                    code,
                    if on {
                        ExceptionPolicyMode::Break
                    } else {
                        ExceptionPolicyMode::SecondChance
                    },
                ),
                FilterEvent::Module(event) => session
                    .set_module_event_filter(
                        event,
                        None,
                        if on {
                            ExceptionPolicyMode::Break
                        } else {
                            ExceptionPolicyMode::Ignore
                        },
                        None,
                    )
                    .map_err(|error| error.to_string())?,
            }
            if on {
                breakpoints.push(json!({"verified": true}));
            }
        }
        Ok(Some(json!({"breakpoints": breakpoints})))
    }
}

/// What an exception filter governs.
#[derive(Clone, Copy)]
pub enum FilterEvent {
    Exception(u32),
    Module(ModuleEvent),
}

/// An exception filter the adapter offers, by its `sx` name.
pub struct ExceptionFilter {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub event: FilterEvent,
    /// Checked unless the client changes it: exceptions break as they do
    /// without a policy, and module events do not stop.
    pub default: bool,
}

/// The filters the adapter offers in `exceptionBreakpointFilters`.
pub const EXCEPTION_FILTERS: &[ExceptionFilter] = &[
    ExceptionFilter {
        name: "av",
        label: "Access violation",
        description: "STATUS_ACCESS_VIOLATION (0xC0000005): break at the first chance, or only at the second when unchecked (sxe/sxd av)",
        event: FilterEvent::Exception(0xc000_0005),
        default: true,
    },
    ExceptionFilter {
        name: "ii",
        label: "Illegal instruction",
        description: "STATUS_ILLEGAL_INSTRUCTION (0xC000001D) (sxe/sxd ii)",
        event: FilterEvent::Exception(0xc000_001d),
        default: true,
    },
    ExceptionFilter {
        name: "dz",
        label: "Integer divide by zero",
        description: "STATUS_INTEGER_DIVIDE_BY_ZERO (0xC0000094) (sxe/sxd dz)",
        event: FilterEvent::Exception(0xc000_0094),
        default: true,
    },
    ExceptionFilter {
        name: "sov",
        label: "Stack overflow",
        description: "STATUS_STACK_OVERFLOW (0xC00000FD) (sxe/sxd sov)",
        event: FilterEvent::Exception(0xc000_00fd),
        default: true,
    },
    ExceptionFilter {
        name: "ld",
        label: "Module load",
        description: "Stop when a driver or module loads (sxe ld)",
        event: FilterEvent::Module(ModuleEvent::Load),
        default: false,
    },
    ExceptionFilter {
        name: "ud",
        label: "Module unload",
        description: "Stop when a driver or module unloads (sxe ud)",
        event: FilterEvent::Module(ModuleEvent::Unload),
        default: false,
    },
];

/// Translate a DAP breakpoint's condition and hit condition into ntoseye's
/// breakpoint configuration. `hitCondition` is a plain pass count, matching
/// WinDbg's `bp <target> <passes>`.
pub(super) fn breakpoint_config(entry: &Value) -> result::Result<BreakpointConfig, String> {
    let pass_count = match arg_str(entry, "hitCondition") {
        Some(text) => {
            let trimmed = text.trim();
            trimmed
                .parse::<u64>()
                .map_err(|_| format!("hit condition '{trimmed}' must be a decimal pass count"))?
        }
        None => 0,
    };
    Ok(BreakpointConfig {
        condition: arg_str(entry, "condition").filter(|text| !text.trim().is_empty()),
        pass_count,
        action: match arg_str(entry, "logMessage") {
            Some(message) => Some(log_point_action(&message)?),
            None => None,
        },
        ..BreakpointConfig::default()
    })
}

/// One breakpoint a `set*Breakpoints` request asks for, resolved as far as
/// possible before the target is halted for the batch.
pub(super) enum Install {
    /// `bu file:line`; may resolve to several addresses.
    Source(String, BreakpointConfig),
    /// `bu symbol`, deferred until its module loads.
    Symbol(String, BreakpointConfig),
    /// `bp address` out of the disassembly view, with no symbol to re-resolve.
    Address(u64, BreakpointConfig),
    /// `ba` on storage a `dataId` already resolved, with no symbol to defer on.
    Watch {
        address: u64,
        access: WatchpointAccess,
        len: u8,
        config: BreakpointConfig,
    },
}

impl Install {
    fn apply(self, session: &mut Session) -> Result<Vec<u32>> {
        match self {
            Self::Source(spec, config) => session.add_source_breakpoint(spec, config),
            Self::Symbol(name, config) => session
                .add_symbol_breakpoint(name, config)
                .map(|id| vec![id]),
            Self::Address(address, config) => session
                .add_breakpoint(VirtAddr(address), None, config)
                .map(|id| vec![id]),
            Self::Watch {
                address,
                access,
                len,
                config,
            } => session
                .add_watchpoint(VirtAddr(address), access, len, None, config)
                .map(|id| vec![id]),
        }
    }
}

/// One session breakpoint a client breakpoint installed. The serial tells it
/// apart from a later breakpoint, such as one set from the debug console,
/// that reuses the id once the session's table empties.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Owned {
    pub id: u32,
    pub serial: u64,
}

/// What one set's install produced, aligned with its plan, and the
/// breakpoints whose removal failed, which stay installed and owned.
type Installed = (Vec<result::Result<Vec<Owned>, String>>, Vec<Owned>);

/// The parts of `groups` whose removal failed, still installed and owned.
fn retain_kept(groups: Vec<Vec<Owned>>, kept: &[Owned]) -> Vec<Vec<Owned>> {
    if kept.is_empty() {
        return Vec::new();
    }
    groups
        .into_iter()
        .map(|group| -> Vec<Owned> {
            group
                .into_iter()
                .filter(|owned| kept.contains(owned))
                .collect()
        })
        .filter(|group| !group.is_empty())
        .collect()
}

/// A breakpoint set the client replaces wholesale with one request.
#[derive(Clone, Copy)]
pub(super) enum OwnedSet {
    Function,
    Instruction,
    Data,
}

/// A breakpoint row the request refused, with the client's line when it had one.
fn refused_breakpoint(message: String, line: Option<i64>) -> Value {
    let mut row = json!({"verified": false, "message": message});
    if let Some(line) = line {
        row["line"] = json!(line);
    }
    row
}

/// Answer a `set*Breakpoints` request without installing anything: every
/// breakpoint it names is unverified, for `reason`. An exception request
/// names its breakpoints as filters, plain and with options.
pub fn unverified(args: &Value, reason: &str) -> Handled {
    let rows: Vec<Value> = ["breakpoints", "filters", "filterOptions"]
        .into_iter()
        .filter_map(|field| args.get(field).and_then(Value::as_array))
        .flatten()
        .map(|entry| refused_breakpoint(reason.to_string(), arg_i64(entry, "line")))
        .collect();
    Ok(Some(json!({"breakpoints": rows})))
}

/// Compile log placeholders into a `.printf` action followed by `gc`.
fn log_point_action(message: &str) -> result::Result<String, String> {
    let mut format = String::new();
    let mut arguments: Vec<String> = Vec::new();
    let mut rest = message;
    while let Some(open) = rest.find('{') {
        format.push_str(&escape_printf(&rest[..open]));
        let tail = &rest[open + 1..];
        let close = tail
            .find('}')
            .ok_or_else(|| format!("log message has an unclosed '{{': {message}"))?;
        // `.printf` takes its arguments as whitespace-separated tokens, so an
        // expression cannot carry spaces. Removing them is safe: ntoseye
        // expressions never contain a significant space.
        let expression: String = tail[..close]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if expression.is_empty() {
            return Err(format!("log message has an empty '{{}}': {message}"));
        }
        // Guard the command grammar: an expression carrying a quote or a
        // semicolon would end the action early.
        if expression.contains(['"', ';']) {
            return Err(format!(
                "log message expression '{expression}' cannot contain a quote or a semicolon"
            ));
        }
        format.push_str("%p");
        arguments.push(expression);
        rest = &tail[close + 1..];
    }
    format.push_str(&escape_printf(rest));
    // `.printf` arguments are whitespace-separated, not comma-separated, and
    // the console already terminates the line, so no trailing newline escape.
    let mut action = format!("\"{format}\"");
    for argument in arguments {
        action.push(' ');
        action.push_str(&argument);
    }
    Ok(format!(".printf {action}; gc"))
}

/// Escape the literal parts of a log message for `.printf`: the quote that
/// would end the format string, the backslash that introduces an escape, and
/// the `%` that would start a specifier.
fn escape_printf(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

/// What the client was last told about a breakpoint, for change detection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct BreakpointState {
    resolved: bool,
    address: VirtAddr,
}

impl From<&BreakpointInfo> for BreakpointState {
    fn from(breakpoint: &BreakpointInfo) -> Self {
        Self {
            resolved: breakpoint.resolved,
            address: breakpoint.address,
        }
    }
}

fn breakpoint_json(breakpoint: &BreakpointInfo, matches: usize) -> Value {
    let mut value = json!({
        "id": breakpoint.id as i64,
        "verified": breakpoint.resolved,
    });
    if breakpoint.resolved {
        value["instructionReference"] = json!(format!("{:#x}", breakpoint.address.0));
    }
    let mut notes = Vec::new();
    if breakpoint.deferred() {
        notes.push(format!(
            "deferred: '{}' is not resolvable yet (it will arm when its module loads)",
            breakpoint.specification().unwrap_or("symbol")
        ));
    }
    if matches > 1 {
        notes.push(format!("{matches} addresses matched"));
    }
    if !notes.is_empty() {
        value["message"] = json!(notes.join("; "));
    }
    value
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::breakpoint_config;

    #[test]
    fn log_points_become_printf_actions_that_resume() {
        let config = breakpoint_config(&json!({"logMessage": "irp {@rcx} status {@rax}"})).unwrap();
        assert_eq!(
            config.action.as_deref(),
            Some(r#".printf "irp %p status %p" @rcx @rax; gc"#)
        );

        // `.printf` splits its arguments on whitespace, so a spaced expression
        // is closed up rather than tokenized into pieces that cannot evaluate.
        let spaced = breakpoint_config(&json!({"logMessage": "at {poi(@rsp + 0x40)}"})).unwrap();
        assert_eq!(
            spaced.action.as_deref(),
            Some(r#".printf "at %p" poi(@rsp+0x40); gc"#)
        );

        // Literal text only: still a print-and-continue, no arguments.
        let plain = breakpoint_config(&json!({"logMessage": "reached unload"})).unwrap();
        assert_eq!(
            plain.action.as_deref(),
            Some(".printf \"reached unload\"; gc")
        );

        // A `%` in the text is a literal, not a format specifier.
        let percent = breakpoint_config(&json!({"logMessage": "100% done"})).unwrap();
        assert_eq!(
            percent.action.as_deref(),
            Some(".printf \"100%% done\"; gc")
        );

        // A placeholder that would break out of the action's quoting is
        // refused rather than silently changing what runs on each hit.
        for bad in [
            "unclosed {@rcx",
            "empty {}",
            "quote {\"}",
            "chain {@rcx; g}",
        ] {
            assert!(
                breakpoint_config(&json!({"logMessage": bad})).is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn blank_conditions_are_not_forwarded_as_expressions() {
        let config = breakpoint_config(&json!({"condition": "   "})).unwrap();
        assert!(config.condition.is_none());
    }
}
