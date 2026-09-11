use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::diagnostics;
use crate::error::Result;
use crate::repl::*;
use crate::symbols::ntoseye_home;

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

    fn insert(&mut self, name: String, expansion: String) -> io::Result<()> {
        self.map.insert(name, expansion);
        self.save()
    }

    fn remove(&mut self, name: &str) -> io::Result<bool> {
        let removed = self.map.remove(name).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
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
        fs::write(path, out)
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
            let index = key
                .parse::<usize>()
                .map_err(|_| format!("invalid alias parameter `${{{key}}}`"))?;
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
    if arg.is_empty() || arg.chars().any(|ch| ch.is_whitespace() || ch == ';') {
        let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        arg.to_string()
    }
}

repl_command! {
    cmd_aliases();
    names: ["aliases"],
    usage: "aliases",
    summary: "List command aliases.",
}

repl_command! {
    cmd_alias;
    names: ["alias"],
    usage: "alias <name> <expansion>",
    summary: "Define a command alias.",
    style: RawTail,
}

repl_command! {
    cmd_unalias;
    names: ["unalias"],
    usage: "unalias <name>",
    summary: "Remove a command alias.",
    completion: Alias,
}

impl ReplState<'_> {
    pub fn reload_aliases(&mut self) -> AliasLoadReport {
        let (aliases, report) = UserAliases::load_with_report();
        self.aliases = aliases;
        self.refresh_alias_cache();
        report
    }

    pub fn refresh_alias_cache(&self) {
        *self.caches.aliases.write().unwrap() = self.aliases.entries();
    }

    fn cmd_alias(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (name, expansion) = match parse_alias_body(invocation.raw_tail) {
            Ok(parts) => parts,
            Err(err) => {
                error!("{}", err);
                return Ok(());
            }
        };
        if let Err(e) = self.aliases.insert(name.to_string(), expansion.to_string()) {
            error!("failed to save aliases: {}", e);
            return Ok(());
        }
        self.refresh_alias_cache();
        outln!("alias {} {}\n", name, expansion);
        Ok(())
    }

    fn cmd_unalias(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let name = require_arg!(invocation, 0, "unalias");
        match self.aliases.remove(name) {
            Ok(true) => {
                self.refresh_alias_cache();
                outln!("unalias {}\n", name);
            }
            Ok(false) => error!("no such alias: {}", name),
            Err(e) => error!("failed to save aliases: {}", e),
        }
        Ok(())
    }

    fn cmd_aliases(&mut self) -> Result<()> {
        if self.aliases.map.is_empty() {
            outln!("no aliases defined\n");
            return Ok(());
        }
        for (name, expansion) in &self.aliases.map {
            outln!("alias {} {}", name, expansion);
        }
        outln!();
        Ok(())
    }
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
}
