use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ntoseye_macros::command;

use crate::base::diagnostics;
use crate::base::error::Result;
use crate::hosts::repl::*;
use crate::nt::symbols::ntoseye_home;

/// Counts the changes to the saved aliases this process made (`as`, `ad`)
/// or read back in (`.reload`), so a REPL state kept between uses can tell
/// that the aliases it loaded are out of date. See [`alias_generation`].
static ALIAS_GENERATION: AtomicU64 = AtomicU64::new(0);

/// The current [`ALIAS_GENERATION`]: aliases loaded at one value are the
/// saved ones until it changes.
pub fn alias_generation() -> u64 {
    ALIAS_GENERATION.load(Ordering::Acquire)
}

#[derive(Clone, Default)]
pub struct UserAliases {
    map: BTreeMap<String, String>,
    path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct AliasLoadReport {
    pub loaded: usize,
    pub failed: Vec<AliasLoadFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasLoadFailure {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub error: String,
}

impl UserAliases {
    pub fn load() -> Self {
        Self::load_with_report().0
    }

    pub fn load_with_report() -> (Self, AliasLoadReport) {
        Self::load_from_path(ntoseye_home().map(|root| root.join("aliases")))
    }

    fn load_from_path(path: Option<PathBuf>) -> (Self, AliasLoadReport) {
        let mut aliases = Self {
            map: BTreeMap::new(),
            path,
        };
        let mut report = AliasLoadReport::default();
        let Some(path) = aliases.path.clone() else {
            return (aliases, report);
        };
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return (aliases, report),
            Err(err) => {
                report.failed.push(AliasLoadFailure {
                    path,
                    line: None,
                    error: err.to_string(),
                });
                return (aliases, report);
            }
        };

        for (idx, line) in contents.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match parse_alias_definition(trimmed) {
                Ok((name, expansion)) => {
                    aliases.map.insert(name.to_string(), expansion.to_string());
                }
                Err(err) => {
                    report.failed.push(AliasLoadFailure {
                        path: path.clone(),
                        line: Some(line_no),
                        error: err,
                    });
                }
            }
        }
        report.loaded = aliases.map.len();
        (aliases, report)
    }

    pub fn entries(&self) -> Vec<(String, String)> {
        self.map
            .iter()
            .map(|(name, expansion)| (name.clone(), expansion.clone()))
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Define `name`, keeping the previous set when it cannot be saved so the
    /// aliases in use always match the file.
    fn insert(&mut self, name: String, expansion: String) -> io::Result<()> {
        let previous = self.map.insert(name.clone(), expansion);
        let saved = self.save();
        if saved.is_err() {
            match previous {
                Some(previous) => self.map.insert(name, previous),
                None => self.map.remove(&name),
            };
        }
        saved
    }

    /// Remove `name`, keeping it when the smaller set cannot be saved.
    fn remove(&mut self, name: &str) -> io::Result<bool> {
        let Some(expansion) = self.map.remove(name) else {
            return Ok(false);
        };
        if let Err(error) = self.save() {
            self.map.insert(name.to_string(), expansion);
            return Err(error);
        }
        Ok(true)
    }

    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = String::new();
        for (name, expansion) in &self.map {
            out.push_str("alias ");
            out.push_str(name);
            out.push(' ');
            out.push_str(expansion);
            out.push('\n');
        }
        fs::write(path, out)?;
        ALIAS_GENERATION.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    pub fn expand(
        &self,
        name: &str,
        args: &[Cow<'_, str>],
    ) -> std::result::Result<Option<String>, String> {
        let Some(template) = self.map.get(name) else {
            return Ok(None);
        };
        expand_alias_template(template, args).map(Some)
    }
}

/// Print a one-line load summary and any failures (used by `.reload`;
/// startup calls [`print_alias_load_failures`] directly).
pub fn print_alias_load_report(report: &AliasLoadReport) {
    let mut summary = format!("aliases: {} loaded", report.loaded);
    if !report.failed.is_empty() {
        summary.push_str(&format!(", {} failed", report.failed.len()));
    }
    outln!("{summary}");
    print_alias_load_failures(report);
}

/// Print per-definition load failures, shared by the reload report and the
/// startup summary line.
pub fn print_alias_load_failures(report: &AliasLoadReport) {
    for failure in &report.failed {
        let location = match failure.line {
            Some(line) => format!("{}:{}", failure.path.display(), line),
            None => failure.path.display().to_string(),
        };
        diagnostics::print_warning(format!("{location}: {}", failure.error));
    }
}

fn parse_alias_definition(line: &str) -> std::result::Result<(&str, &str), String> {
    let Some(rest) = line.strip_prefix("alias ") else {
        return Err("expected `alias <name> <expansion>`".to_string());
    };
    parse_alias_body(rest)
}

fn parse_alias_body(body: &str) -> std::result::Result<(&str, &str), String> {
    let body = body.trim();
    let Some((split, ch)) = body.char_indices().find(|(_, ch)| ch.is_whitespace()) else {
        return Err("expected `alias <name> <expansion>`".to_string());
    };
    let name = &body[..split];
    let expansion = body[split + ch.len_utf8()..].trim();
    validate_alias_name(name)?;
    if expansion.is_empty() {
        return Err("alias expansion cannot be empty".to_string());
    }
    Ok((name, expansion))
}

fn validate_alias_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() || name.chars().any(|ch| ch.is_whitespace() || ch == ';') {
        return Err("invalid alias name".to_string());
    }
    // WinDbg's `as` takes options (`/e`, `/ma`, `/f`) that select where the
    // value comes from. None are implemented, and an unrecognized option must
    // not quietly become an alias literally named `/e`.
    if name.starts_with('/') {
        return Err(format!(
            "alias options are not supported (got `{name}`); use `as <name> <expansion>`"
        ));
    }
    if command_registry().get(name).is_some() {
        return Err(format!("alias `{name}` would shadow a built-in command"));
    }
    Ok(())
}

fn expand_alias_template(
    template: &str,
    args: &[Cow<'_, str>],
) -> std::result::Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(format!(
                "unterminated alias placeholder at `{}`",
                &rest[start..]
            ));
        };
        let key = &after_start[..end];
        if key == "*" {
            out.push_str(
                &args
                    .iter()
                    .map(|arg| quote_alias_arg(arg.as_ref()))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        } else {
            // Anything but a parameter number is someone else's name: loop
            // variables and `!for_each_*` aliases (`${@#ModuleName}`) are
            // replaced when the loop runs.
            let Ok(index) = key.parse::<usize>() else {
                out.push_str(&rest[start..start + 2 + end + 1]);
                rest = &after_start[end + 1..];
                continue;
            };
            let Some(arg) = index.checked_sub(1).and_then(|idx| args.get(idx)) else {
                return Err(format!("missing alias argument `${{{key}}}`"));
            };
            out.push_str(&quote_alias_arg(arg.as_ref()));
        }
        rest = &after_start[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn quote_alias_arg(arg: &str) -> String {
    if arg.is_empty() || arg.contains(char::is_whitespace) || breaks_command_line(arg) {
        quote_arg(arg)
    } else {
        arg.to_string()
    }
}

/// Whether `value`, spliced raw into a command line, could end a command or
/// a quoted argument early: it holds a `;` or a quote.
fn breaks_command_line(value: &str) -> bool {
    value.contains([';', '"', '\''])
}

/// `value` as one quoted argument, escaped as command arguments are.
pub fn quote_arg(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// `value` ready to splice into a command line it did not come from (a
/// guest string, a `.foreach` token): quoted when it holds a `;` or a quote,
/// so it cannot end the command it lands in and start another. Whitespace
/// is left alone, so a value may still become several arguments, as with
/// WinDbg's substitution.
pub fn splice_value(value: &str) -> Cow<'_, str> {
    if breaks_command_line(value) {
        Cow::Owned(quote_arg(value))
    } else {
        Cow::Borrowed(value)
    }
}

impl ReplState<'_> {
    /// Read the saved aliases back in, which tells every other REPL state
    /// kept between uses to read them too: the file may have changed under
    /// all of them.
    pub fn reload_aliases(&mut self) -> AliasLoadReport {
        ALIAS_GENERATION.fetch_add(1, Ordering::AcqRel);
        let (aliases, report) = UserAliases::load_with_report();
        self.aliases = aliases;
        self.refresh_alias_cache();
        report
    }

    pub fn refresh_alias_cache(&self) {
        *self.caches.aliases.write().unwrap() = self.aliases.entries();
    }
}

/// List command aliases.
#[command(names = ["al", "aliases"], category = "session", kind = Host, python = none)]
fn aliases(state: &mut ReplState<'_>) -> Result<()> {
    if state.aliases.map.is_empty() {
        outln!("no aliases defined");
        return Ok(());
    }
    for (name, expansion) in &state.aliases.map {
        outln!("alias {} {}", name, expansion);
    }
    Ok(())
}

/// Define a command alias.
#[command(
    names = ["as", "alias"],
    category = "session",
    kind = Host,
    python = none,
    style = RawTail
)]
fn alias(
    state: &mut ReplState<'_>,
    #[arg(raw, usage = "<name> <expansion>", complete = None)] tail: String,
) -> Result<()> {
    let (name, expansion) = match parse_alias_body(tail.as_str()) {
        Ok(parts) => parts,
        Err(err) => {
            error!("{}", err);
            return Ok(());
        }
    };
    if let Err(e) = state
        .aliases
        .insert(name.to_string(), expansion.to_string())
    {
        error!("failed to save aliases: {}", e);
        return Ok(());
    }
    state.refresh_alias_cache();
    outln!("defined alias {name} as {expansion}");
    Ok(())
}

/// Remove a command alias.
#[command(
    names = ["ad", "unalias"],
    category = "session",
    kind = Host,
    python = none,
)]
fn unalias(state: &mut ReplState<'_>, #[arg(complete = Alias)] name: String) -> Result<()> {
    match state.aliases.remove(&name) {
        Ok(true) => {
            state.refresh_alias_cache();
            outln!("removed alias {name}");
        }
        Ok(false) => error!("alias '{name}' not found"),
        Err(e) => error!("failed to save aliases: {}", e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alias_body_from_first_whitespace() {
        assert_eq!(
            parse_alias_body("ubp bp ${1}; g").unwrap(),
            ("ubp", "bp ${1}; g")
        );
    }

    #[test]
    fn alias_expansion_can_contain_equals() {
        assert_eq!(
            parse_alias_body("setfoo set $foo = ${1}").unwrap(),
            ("setfoo", "set $foo = ${1}")
        );
    }

    #[test]
    fn alias_body_requires_expansion() {
        assert_eq!(
            parse_alias_body("ubp").unwrap_err(),
            "expected `alias <name> <expansion>`"
        );
        assert_eq!(
            parse_alias_body("ubp   ").unwrap_err(),
            "expected `alias <name> <expansion>`"
        );
    }

    #[test]
    fn expands_positional_parameters() {
        let args = vec!["nt!KeBugCheck".into(), "extra arg".into()];
        assert_eq!(
            expand_alias_template("bp ${1}; g ${2}", &args).unwrap(),
            "bp nt!KeBugCheck; g \"extra arg\""
        );
    }

    #[test]
    fn missing_positional_parameter_is_error() {
        let err = expand_alias_template("bp ${2}", &[]).unwrap_err();
        assert_eq!(err, "missing alias argument `${2}`");
    }

    #[test]
    fn loop_names_pass_through_for_the_loop_to_replace() {
        let args = [Cow::Borrowed("Sym")];
        assert_eq!(
            expand_alias_template("!for_each_module \"x ${@#ModuleName}!${1}\"", &args).unwrap(),
            "!for_each_module \"x ${@#ModuleName}!Sym\""
        );
    }

    #[test]
    fn expands_star_parameter() {
        let args = vec!["one".into(), "two words".into()];
        assert_eq!(
            expand_alias_template("k ${*}", &args).unwrap(),
            "k one \"two words\""
        );
    }

    #[test]
    fn rejects_builtin_shadowing() {
        assert_eq!(
            validate_alias_name("g").unwrap_err(),
            "alias `g` would shadow a built-in command"
        );
    }

    #[test]
    fn load_report_counts_aliases_and_failures() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ntoseye-alias-test-{nonce}"));
        let path = dir.join("aliases");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            "alias ubp bp ${1}; g\nnot an alias\nalias kx k ${*}\n",
        )
        .unwrap();

        let (aliases, report) = UserAliases::load_from_path(Some(path.clone()));

        assert_eq!(report.loaded, 2);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].path, path);
        assert_eq!(report.failed[0].line, Some(2));
        assert_eq!(
            report.failed[0].error,
            "expected `alias <name> <expansion>`"
        );
        assert_eq!(
            aliases.entries(),
            vec![
                ("kx".to_string(), "k ${*}".to_string()),
                ("ubp".to_string(), "bp ${1}; g".to_string()),
            ]
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A definition or removal that cannot be saved leaves the aliases in
    /// use as the file has them.
    #[test]
    fn failed_save_keeps_the_previous_aliases() {
        // A directory where the file belongs makes every save fail.
        let mut aliases = UserAliases {
            map: BTreeMap::from([("ubp".to_string(), "bp ${1}".to_string())]),
            path: Some(std::env::temp_dir()),
        };
        let before = aliases.entries();

        assert!(aliases.insert("kx".into(), "k".into()).is_err());
        assert!(aliases.insert("ubp".into(), "bp ${2}".into()).is_err());
        assert!(aliases.remove("ubp").is_err());
        assert!(!aliases.remove("kx").unwrap());
        assert_eq!(aliases.entries(), before);
    }
}
