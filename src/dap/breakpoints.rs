//! Client breakpoint sets (source, function, instruction, data), each
//! replaced in one halt, and verification changes reported as they happen.

use std::result;

use serde_json::{Value, json};

use crate::breakpoints::{Breakpoint, BreakpointConfig};
use crate::dbg_backend::WatchpointAccess;
use crate::error::Result;
use crate::session::Session;
use crate::types::VirtAddr;

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
        let tracked: Vec<u32> = self
            .source_breakpoints
            .values()
            .flatten()
            .flatten()
            .copied()
            .chain(self.function_breakpoints.iter().copied())
            .chain(self.instruction_breakpoints.iter().copied())
            .chain(self.data_breakpoints.iter().copied())
            .collect();
        for id in tracked {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            let Some(breakpoint) = session.breakpoint(id) else {
                self.verified.remove(&id);
                continue;
            };
            let state = BreakpointState::from(breakpoint);
            if self.verified.insert(id, state) == Some(state) {
                continue;
            }
            let Some(breakpoint) = self.session.as_ref().and_then(|s| s.breakpoint(id)) else {
                continue;
            };
            let body = json!({"reason": "changed", "breakpoint": breakpoint_json(breakpoint, 1)});
            self.send_event("breakpoint", body);
        }
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
        let previous: Vec<u32> = self
            .source_breakpoints
            .get(&key)
            .into_iter()
            .flatten()
            .flatten()
            .copied()
            .collect();
        let results = self.install_breakpoints(previous, plan)?;
        self.source_breakpoints.remove(&key);
        let mut installed = Vec::with_capacity(results.len());
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

    fn owned_set(&mut self, set: OwnedSet) -> &mut Vec<u32> {
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
        let previous = self.owned_set(set).clone();
        let results = self.install_breakpoints(previous, plan)?;
        self.owned_set(set).clear();
        let mut response = Vec::with_capacity(results.len());
        for result in results {
            match result {
                Ok(ids) => {
                    response.push(self.breakpoint_value(&ids, None));
                    self.owned_set(set).extend(ids);
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
    /// edits stand, and the next service tick surfaces the halt.
    fn install_breakpoints(
        &mut self,
        remove: Vec<u32>,
        mut plan: Vec<result::Result<Install, String>>,
    ) -> result::Result<Vec<result::Result<Vec<u32>, String>>, String> {
        let session = self.session()?;
        let mut results = Vec::with_capacity(plan.len());
        let mut edited = false;
        let outcome = session.with_target_halted(|session| {
            edited = true;
            for id in &remove {
                let _ = session.remove_breakpoint(*id);
            }
            results.extend(plan.drain(..).map(|slot| {
                slot.and_then(|install| install.apply(session).map_err(|error| error.to_string()))
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
        for id in &remove {
            self.verified.remove(id);
        }
        Ok(results)
    }

    /// Report one installed breakpoint: verified once an address is resolved,
    /// unverified (with the reason) while it stays deferred.
    fn breakpoint_value(&mut self, ids: &[u32], line: Option<i64>) -> Value {
        let Some(session) = self.session.as_ref() else {
            return json!({"verified": false, "message": "no target attached"});
        };
        let first = ids.first().and_then(|id| session.breakpoint(*id));
        // One client breakpoint can install several ids (a source line with
        // more than one address). `reconcile_breakpoints` walks all of them, so
        // all of them have to be seeded here or the ids the client never saw
        // each report a spurious change at the next stop.
        let states: Vec<(u32, BreakpointState)> = ids
            .iter()
            .filter_map(|id| {
                session
                    .breakpoint(*id)
                    .map(|breakpoint| (*id, BreakpointState::from(breakpoint)))
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

    /// Accept an empty filter list; reject unsupported exception filters.
    pub(super) fn on_set_exception_breakpoints(args: &Value) -> Handled {
        for field in ["filters", "filterOptions", "exceptionOptions"] {
            let requested = args
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|entries| !entries.is_empty());
            if requested {
                return Err(format!(
                    "exception breakpoints are not supported; '{field}' cannot be honored. \
                     Use the REPL's `sx` commands for exception policy"
                ));
            }
        }
        Ok(Some(json!({"breakpoints": []})))
    }
}

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

impl From<&Breakpoint> for BreakpointState {
    fn from(breakpoint: &Breakpoint) -> Self {
        Self {
            resolved: breakpoint.resolved,
            address: breakpoint.address,
        }
    }
}

fn breakpoint_json(breakpoint: &Breakpoint, matches: usize) -> Value {
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
