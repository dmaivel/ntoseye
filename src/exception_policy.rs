use std::collections::BTreeMap;

use crate::dbg_backend::{ContinueDisposition, StopEvent};
use crate::symbols::glob_matches;

const STATUS_BREAKPOINT: u32 = 0x8000_0003;
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
pub const EXCEPTION_COMMAND_RECURSION_LIMIT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExceptionPolicyMode {
    Break,
    SecondChance,
    Notify,
    Ignore,
}

impl ExceptionPolicyMode {
    /// The mode's name in structured output and the SDK.
    pub fn name(self) -> &'static str {
        match self {
            Self::Break => "break",
            Self::SecondChance => "second_chance",
            Self::Notify => "notify",
            Self::Ignore => "ignore",
        }
    }

    pub fn command(self) -> &'static str {
        match self {
            Self::Break => "sxe",
            Self::SecondChance => "sxd",
            Self::Notify => "sxn",
            Self::Ignore => "sxi",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Break => "break",
            Self::SecondChance => "second chance",
            Self::Notify => "notify",
            Self::Ignore => "ignore",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExceptionPolicyFinalAction {
    Break,
    Continue(ContinueDisposition),
}

impl ExceptionPolicyFinalAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Break => "break",
            Self::Continue(ContinueDisposition::Handled) => "gh",
            Self::Continue(ContinueDisposition::NotHandled) => "gn",
        }
    }
}

pub fn parse_exception_final_action(value: &str) -> Result<ExceptionPolicyFinalAction, String> {
    match value.to_ascii_lowercase().as_str() {
        "break" => Ok(ExceptionPolicyFinalAction::Break),
        "g" | "gh" | "handled" => Ok(ExceptionPolicyFinalAction::Continue(
            ContinueDisposition::Handled,
        )),
        "gn" | "not-handled" | "not_handled" => Ok(ExceptionPolicyFinalAction::Continue(
            ContinueDisposition::NotHandled,
        )),
        _ => Err(format!(
            "invalid final action '{value}' (use break, gh, or gn)"
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExceptionPolicyAction {
    Surface {
        command: Option<String>,
    },
    Continue {
        notify: bool,
        disposition: ContinueDisposition,
        command: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionPolicy {
    pub mode: ExceptionPolicyMode,
    pub command: Option<String>,
    pub final_action: Option<ExceptionPolicyFinalAction>,
}

/// A module-load event filter (`sx* ld[:<module>]`). `module` is a
/// case-insensitive `*`/`?` glob over the image name, with or without its
/// extension; `None` (bare `ld`) matches every image. Only `Break` stops and
/// only `Notify` reports; `command` runs at a `Break` stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleLoadPolicy {
    pub module: Option<String>,
    pub mode: ExceptionPolicyMode,
    pub command: Option<String>,
}

impl ModuleLoadPolicy {
    /// Whether this filter names the image `name` (a file name or path).
    pub fn matches(&self, name: &str) -> bool {
        let Some(pattern) = self.module.as_deref() else {
            return true;
        };
        let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let stem = file.rsplit_once('.').map_or(file, |(stem, _)| stem);
        glob_matches(pattern, file, true) || glob_matches(pattern, stem, true)
    }

    /// The filter as `sx` spells it: `ld` or `ld:<module>`.
    pub fn event_name(&self) -> String {
        match &self.module {
            Some(module) => format!("ld:{module}"),
            None => "ld".to_string(),
        }
    }
}

/// What an `sx*` argument names: an exception code, or the module-load event
/// with its optional module filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventFilter {
    Exception(u32),
    ModuleLoad(Option<String>),
}

#[derive(Default)]
pub struct ExceptionPolicyTable {
    policies: BTreeMap<u32, ExceptionPolicy>,
    /// In the order they were set; a module's latest setting replaces its
    /// earlier one.
    module_loads: Vec<ModuleLoadPolicy>,
}

impl ExceptionPolicyTable {
    pub fn set(&mut self, code: u32, mode: ExceptionPolicyMode) {
        self.set_with_options(code, mode, None, None);
    }

    pub fn set_with_options(
        &mut self,
        code: u32,
        mode: ExceptionPolicyMode,
        command: Option<String>,
        final_action: Option<ExceptionPolicyFinalAction>,
    ) {
        self.policies.insert(
            code,
            ExceptionPolicy {
                mode,
                command,
                final_action,
            },
        );
    }

    pub fn reset(&mut self) {
        self.policies.clear();
        self.module_loads.clear();
    }

    pub fn entries(&self) -> impl Iterator<Item = (u32, &ExceptionPolicy)> + '_ {
        self.policies.iter().map(|(&code, policy)| (code, policy))
    }

    pub fn mode_for(&self, code: u32) -> Option<ExceptionPolicyMode> {
        self.policies.get(&code).map(|policy| policy.mode)
    }

    /// Set the module-load filter for `module` (`None`: every module),
    /// replacing an earlier one for the same module.
    pub fn set_module_load(
        &mut self,
        module: Option<String>,
        mode: ExceptionPolicyMode,
        command: Option<String>,
    ) {
        let same = |policy: &ModuleLoadPolicy| match (&policy.module, &module) {
            (Some(existing), Some(module)) => existing.eq_ignore_ascii_case(module),
            (None, None) => true,
            _ => false,
        };
        self.module_loads.retain(|policy| !same(policy));
        self.module_loads.push(ModuleLoadPolicy {
            module,
            mode,
            command,
        });
    }

    pub fn module_load_entries(&self) -> impl Iterator<Item = &ModuleLoadPolicy> + '_ {
        self.module_loads.iter()
    }

    /// The filter that applies to a load of the image `name`: the most
    /// recently set one naming it, else the bare `ld` filter.
    pub fn module_load_policy(&self, name: &str) -> Option<&ModuleLoadPolicy> {
        let named = self
            .module_loads
            .iter()
            .rev()
            .find(|policy| policy.module.is_some() && policy.matches(name));
        named.or_else(|| {
            self.module_loads
                .iter()
                .find(|policy| policy.module.is_none())
        })
    }

    /// Classify only ordinary target exceptions. Debugger-managed control stops
    /// retain their existing handlers and never run policy command strings.
    pub fn action_for(&self, event: &StopEvent) -> ExceptionPolicyAction {
        let surface_without_command = || ExceptionPolicyAction::Surface { command: None };
        if event.is_bugcheck
            || event.target_reloaded
            || event.assisted_breakin
            || matches!(
                event.exception_code,
                Some(STATUS_BREAKPOINT | STATUS_SINGLE_STEP)
            )
        {
            return surface_without_command();
        }

        let Some(code) = event.exception_code else {
            return surface_without_command();
        };
        let Some(policy) = self.policies.get(&code) else {
            return surface_without_command();
        };

        let default_action = match (policy.mode, event.first_chance) {
            (ExceptionPolicyMode::Break, _)
            | (ExceptionPolicyMode::SecondChance, Some(false))
            | (ExceptionPolicyMode::SecondChance, None)
            | (ExceptionPolicyMode::Notify | ExceptionPolicyMode::Ignore, None) => {
                ExceptionPolicyFinalAction::Break
            }
            (ExceptionPolicyMode::SecondChance, Some(true))
            | (ExceptionPolicyMode::Notify, Some(_))
            | (ExceptionPolicyMode::Ignore, Some(_)) => {
                ExceptionPolicyFinalAction::Continue(ContinueDisposition::NotHandled)
            }
        };
        match policy.final_action.unwrap_or(default_action) {
            ExceptionPolicyFinalAction::Break => ExceptionPolicyAction::Surface {
                command: policy.command.clone(),
            },
            ExceptionPolicyFinalAction::Continue(disposition) => ExceptionPolicyAction::Continue {
                notify: policy.mode == ExceptionPolicyMode::Notify,
                disposition,
                command: policy.command.clone(),
            },
        }
    }
}

/// Parse an `sx*` event argument: `ld`, `ld:<module>`, or an exception code
/// or alias. Module unload (`ud`) is refused.
pub fn parse_event_filter(value: &str) -> Result<EventFilter, String> {
    let trimmed = value.trim();
    let (event, argument) = match trimmed.split_once(':') {
        Some((event, argument)) => (event, Some(argument.trim())),
        None => (trimmed, None),
    };
    if event.eq_ignore_ascii_case("ld") {
        return match argument {
            Some("") => Err(format!("'{value}' names no module (use ld or ld:<module>)")),
            argument => Ok(EventFilter::ModuleLoad(argument.map(str::to_string))),
        };
    }
    if event.eq_ignore_ascii_case("ud") {
        return Err(format!(
            "event '{value}' is not configurable: module unload filters are not supported"
        ));
    }
    parse_exception_code(trimmed).map(EventFilter::Exception)
}

fn parse_exception_code(value: &str) -> Result<u32, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if let Some((_, code)) = EXCEPTION_ALIASES
        .iter()
        .find(|(alias, _)| *alias == normalized)
    {
        return Ok(*code);
    }

    let digits = normalized.strip_prefix("0x").unwrap_or(&normalized);
    u32::from_str_radix(digits, 16)
        .map_err(|_| format!("unknown exception alias or hexadecimal code '{value}'"))
}

pub fn exception_alias(code: u32) -> Option<&'static str> {
    EXCEPTION_ALIASES
        .iter()
        .find_map(|(alias, alias_code)| (*alias_code == code).then_some(*alias))
}

// WinDbg's commonly used exception-filter aliases. Event aliases that are not
// exception codes (process/thread/module creation) intentionally do not live in
// this numeric exception policy table.
const EXCEPTION_ALIASES: &[(&str, u32)] = &[
    ("asrt", 0x4000_0015), // STATUS_FATAL_APP_EXIT / assertion filter
    ("av", 0xc000_0005),
    ("bp", STATUS_BREAKPOINT),
    ("dm", 0x8000_0002),
    ("dz", 0xc000_0094),
    ("eh", 0xe06d_7363),
    ("cc", 0xe06d_7363),
    ("gp", 0x8000_0001),
    ("ii", 0xc000_001d),
    ("iov", 0xc000_0095),
    ("ip", 0xc000_0006),
    ("isc", 0xc000_001c),
    ("lsq", 0xc000_001e),
    ("sbo", 0xc000_0409),
    ("sse", STATUS_SINGLE_STEP),
    ("sov", 0xc000_00fd),
    ("wos", 0x4000_001e),
    ("wob", 0x4000_001f),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn event(code: u32, first_chance: Option<bool>) -> StopEvent {
        StopEvent {
            thread_id: Some("p1.1".into()),
            exception_code: Some(code),
            first_chance,
            exception_address: Some(0xffff_f800_1234_5678),
            program_counter: Some(0xffff_f800_1234_5678),
            watchpoint_address: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            modules_changed: false,
            loaded_image_base: None,
            assisted_breakin: false,
        }
    }

    #[test]
    fn parses_common_aliases_and_hex_codes() {
        assert_eq!(parse_exception_code("av").unwrap(), 0xc000_0005);
        assert_eq!(parse_exception_code("bp").unwrap(), STATUS_BREAKPOINT);
        assert_eq!(parse_exception_code("sse").unwrap(), STATUS_SINGLE_STEP);
        assert_eq!(parse_exception_code("SOV").unwrap(), 0xc000_00fd);
        assert_eq!(parse_exception_code("0xC0000094").unwrap(), 0xc000_0094);
        assert_eq!(parse_exception_code("c000001d").unwrap(), 0xc000_001d);
        assert!(parse_exception_code("not-an-event").is_err());
    }

    #[test]
    fn second_chance_policy_passes_first_and_surfaces_second() {
        let mut policies = ExceptionPolicyTable::default();
        policies.set(0xc000_0005, ExceptionPolicyMode::SecondChance);

        assert_eq!(
            policies.action_for(&event(0xc000_0005, Some(true))),
            ExceptionPolicyAction::Continue {
                notify: false,
                disposition: ContinueDisposition::NotHandled,
                command: None,
            }
        );
        assert_eq!(
            policies.action_for(&event(0xc000_0005, Some(false))),
            ExceptionPolicyAction::Surface { command: None }
        );
        assert_eq!(
            policies.action_for(&event(0xc000_0005, None)),
            ExceptionPolicyAction::Surface { command: None }
        );
    }

    #[test]
    fn policies_never_absorb_debugger_control_stops() {
        let mut policies = ExceptionPolicyTable::default();
        policies.set(STATUS_BREAKPOINT, ExceptionPolicyMode::Ignore);
        policies.set(STATUS_SINGLE_STEP, ExceptionPolicyMode::Ignore);
        policies.set(0xc000_0005, ExceptionPolicyMode::Ignore);

        assert_eq!(
            policies.action_for(&event(STATUS_BREAKPOINT, Some(true))),
            ExceptionPolicyAction::Surface { command: None }
        );
        assert_eq!(
            policies.action_for(&event(STATUS_SINGLE_STEP, Some(true))),
            ExceptionPolicyAction::Surface { command: None }
        );

        let mut protected = event(0xc000_0005, Some(true));
        protected.is_bugcheck = true;
        assert_eq!(
            policies.action_for(&protected),
            ExceptionPolicyAction::Surface { command: None }
        );
        protected.is_bugcheck = false;
        protected.target_reloaded = true;
        assert_eq!(
            policies.action_for(&protected),
            ExceptionPolicyAction::Surface { command: None }
        );
        protected.target_reloaded = false;
        protected.assisted_breakin = true;
        assert_eq!(
            policies.action_for(&protected),
            ExceptionPolicyAction::Surface { command: None }
        );
    }

    #[test]
    fn command_and_explicit_final_action_are_typed_policy_outcomes() {
        let mut policies = ExceptionPolicyTable::default();
        policies.set_with_options(
            0xc000_0005,
            ExceptionPolicyMode::Break,
            Some("registers".into()),
            Some(ExceptionPolicyFinalAction::Continue(
                ContinueDisposition::Handled,
            )),
        );

        assert_eq!(
            policies.action_for(&event(0xc000_0005, Some(true))),
            ExceptionPolicyAction::Continue {
                notify: false,
                disposition: ContinueDisposition::Handled,
                command: Some("registers".into()),
            }
        );
        assert_eq!(
            parse_exception_final_action("break").unwrap(),
            ExceptionPolicyFinalAction::Break
        );
        assert_eq!(
            parse_exception_final_action("gn").unwrap(),
            ExceptionPolicyFinalAction::Continue(ContinueDisposition::NotHandled)
        );
        assert!(parse_exception_final_action("continue-somehow").is_err());
    }

    #[test]
    fn event_filters_parse_module_loads_and_refuse_unloads() {
        assert_eq!(
            parse_event_filter("ld").unwrap(),
            EventFilter::ModuleLoad(None)
        );
        assert_eq!(
            parse_event_filter("LD:PdbProbe.sys").unwrap(),
            EventFilter::ModuleLoad(Some("PdbProbe.sys".into()))
        );
        assert_eq!(
            parse_event_filter("av").unwrap(),
            EventFilter::Exception(0xc000_0005)
        );
        assert!(parse_event_filter("ld:").is_err());
        assert!(parse_event_filter("ud").is_err());
        assert!(parse_event_filter("ud:pdbprobe").is_err());
    }

    #[test]
    fn module_load_filters_match_image_names_with_or_without_extension() {
        let filter = |module: &str| ModuleLoadPolicy {
            module: Some(module.into()),
            mode: ExceptionPolicyMode::Break,
            command: None,
        };
        assert!(filter("pdbprobe").matches("PdbProbe.sys"));
        assert!(filter("PDBPROBE.SYS").matches("PdbProbe.sys"));
        assert!(filter("pdbprobe").matches(r"\SystemRoot\System32\drivers\PdbProbe.sys"));
        assert!(filter("pdb*").matches("PdbProbe.sys"));
        assert!(filter("pdbprob?").matches("PdbProbe.sys"));
        assert!(filter("*.sys").matches("PdbProbe.sys"));
        assert!(!filter("pdbprobe").matches("PdbProbe2.sys"));
        assert!(!filter("probe").matches("PdbProbe.sys"));
        assert!(!filter("pdbprobe.dll").matches("PdbProbe.sys"));
    }

    #[test]
    fn a_named_module_load_filter_takes_precedence_over_bare_ld() {
        let mut policies = ExceptionPolicyTable::default();
        assert_eq!(policies.module_load_policy("PdbProbe.sys"), None);

        policies.set_module_load(None, ExceptionPolicyMode::Break, None);
        policies.set_module_load(Some("pdbprobe".into()), ExceptionPolicyMode::Ignore, None);
        let mode = |policies: &ExceptionPolicyTable, name| {
            policies.module_load_policy(name).map(|policy| policy.mode)
        };
        assert_eq!(
            mode(&policies, "PdbProbe.sys"),
            Some(ExceptionPolicyMode::Ignore)
        );
        assert_eq!(
            mode(&policies, "appid.sys"),
            Some(ExceptionPolicyMode::Break)
        );

        // Setting a module again replaces its filter, whatever its case.
        policies.set_module_load(Some("PDBPROBE".into()), ExceptionPolicyMode::Notify, None);
        assert_eq!(policies.module_load_entries().count(), 2);
        assert_eq!(
            mode(&policies, "PdbProbe.sys"),
            Some(ExceptionPolicyMode::Notify)
        );

        // Of two named filters for one image, the later one applies.
        policies.set_module_load(Some("pdb*".into()), ExceptionPolicyMode::Break, None);
        assert_eq!(
            mode(&policies, "PdbProbe.sys"),
            Some(ExceptionPolicyMode::Break)
        );

        policies.reset();
        assert_eq!(mode(&policies, "PdbProbe.sys"), None);
    }
}
