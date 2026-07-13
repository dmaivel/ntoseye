use nu_ansi_term::Style;
use reedline::{
    Completer, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Span,
    Suggestion,
};
use reedline::{Highlighter, StyledText};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use owo_colors::OwoColorize;
use std::borrow::Cow;

use crate::expr::Expr;

use crate::repl::*;

#[derive(Clone)]
pub struct CustomPrompt;
const DEFAULT_MULTILINE_INDICATOR: &str = "     ::: ";
impl Prompt for CustomPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned("ntoseye>".bright_black().to_string())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Owned("".into())
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(" ".to_string())
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(DEFAULT_MULTILINE_INDICATOR)
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

fn make_suggestions(
    names: Vec<String>,
    description: &str,
    span_start: usize,
    pos: usize,
) -> Vec<Suggestion> {
    names
        .into_iter()
        .map(|name| Suggestion {
            value: name,
            description: Some(description.to_string()),
            style: None,
            extra: None,
            match_indices: None,
            span: Span::new(span_start, pos),
            append_whitespace: false,
            display_override: None,
        })
        .collect()
}

pub struct MyCompleter {
    pub caches: ReplCaches,
}

#[derive(Clone, Copy)]
struct CompletionInput<'a> {
    raw_prefix: &'a str,
    ident_start: usize,
    prefix: &'a str,
    arg_start: usize,
    span_start: usize,
    pos: usize,
}

impl<'a> CompletionInput<'a> {
    fn new(text_before_cursor: &'a str, pos: usize) -> Self {
        let arg_start = text_before_cursor
            .char_indices()
            .rfind(|(_, ch)| ch.is_whitespace())
            .map(|(i, ch)| i + ch.len_utf8())
            .unwrap_or(0);
        let raw_prefix = &text_before_cursor[arg_start..];

        // Find the start of the identifier being typed by scanning backward for
        // expression boundary characters (operators, parens, dereference).
        let ident_start = raw_prefix
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map(|i| i + 1)
            .unwrap_or(0);
        let prefix = &raw_prefix[ident_start..];
        let span_start = arg_start + ident_start;

        Self {
            raw_prefix,
            ident_start,
            prefix,
            arg_start,
            span_start,
            pos,
        }
    }

    fn preceding(self) -> &'a str {
        &self.raw_prefix[..self.ident_start]
    }
}

fn completion_arg_index(text_before_cursor: &str) -> usize {
    let Ok(Some(parsed)) = parse_command(text_before_cursor) else {
        return 0;
    };
    let style = command_registry()
        .get(parsed.name)
        .map(|spec| spec.style)
        .unwrap_or(CommandStyle::StructuredArgs);
    let Ok(invocation) = parsed.invocation(style) else {
        return 0;
    };
    let count =
        1 + invocation.argv.len() + usize::from(text_before_cursor.ends_with(char::is_whitespace));
    count.saturating_sub(2)
}

impl Completer for MyCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let text_before_cursor = &line[..pos];
        let parsed = match parse_command(text_before_cursor) {
            Ok(parsed) => parsed,
            Err(_) => return vec![],
        };
        let command_str = parsed.as_ref().map(|parsed| parsed.name).unwrap_or("");
        let is_command_context = parsed.as_ref().is_none_or(|parsed| {
            parsed.raw_tail.is_empty() && !text_before_cursor.ends_with(char::is_whitespace)
        });

        if is_command_context {
            let mut suggestions: Vec<Suggestion> = command_registry()
                .command_names()
                .into_iter()
                .filter_map(|(name, spec)| {
                    if name.starts_with(command_str) {
                        Some(Suggestion {
                            value: name.to_string(),
                            description: Some(spec.summary.to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                            display_override: None,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            {
                let user_cmds = self.caches.user_commands.read().unwrap();
                for (name, help, _) in user_cmds.iter() {
                    if name.starts_with(command_str) {
                        suggestions.push(Suggestion {
                            value: name.clone(),
                            description: Some(help.clone()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                            display_override: None,
                        });
                    }
                }
            }
            {
                let aliases = self.caches.aliases.read().unwrap();
                for (name, _) in aliases.iter() {
                    if name.starts_with(command_str) {
                        suggestions.push(Suggestion {
                            value: name.clone(),
                            description: Some("Alias".to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                            display_override: None,
                        });
                    }
                }
            }
            return suggestions;
        }

        if let Some(spec) = command_registry().get(command_str) {
            let input = CompletionInput::new(text_before_cursor, pos);
            let strategy = spec
                .completion
                .strategy_for_arg(completion_arg_index(text_before_cursor));
            return self.apply_strategy(strategy, input);
        }

        {
            // Fallback: script-registered command with per-arg completion hints
            let user_cmds = self.caches.user_commands.read().unwrap();
            if let Some((_, _, strategies)) = user_cmds.iter().find(|(n, _, _)| n == command_str) {
                let arg_index = completion_arg_index(text_before_cursor);
                let strat = strategies
                    .get(arg_index)
                    .copied()
                    .unwrap_or(CompletionStrategy::None);

                return self.apply_strategy(strat, CompletionInput::new(text_before_cursor, pos));
            }
        }

        let alias_expansion = {
            let aliases = self.caches.aliases.read().unwrap();
            aliases
                .iter()
                .find(|(name, _)| name == command_str)
                .map(|(_, expansion)| expansion.clone())
        };
        if let Some(expansion) = alias_expansion {
            let arg_index = completion_arg_index(text_before_cursor);
            let strategy = {
                let user_cmds = self.caches.user_commands.read().unwrap();
                infer_alias_completion_strategy(&expansion, arg_index, &user_cmds)
            };
            return self.apply_strategy(strategy, CompletionInput::new(text_before_cursor, pos));
        }

        vec![]
    }
}

impl MyCompleter {
    fn apply_strategy(
        &self,
        strategy: CompletionStrategy,
        input: CompletionInput<'_>,
    ) -> Vec<Suggestion> {
        match strategy {
            CompletionStrategy::None => vec![],

            CompletionStrategy::Symbol => self.complete_symbol(input, true),
            CompletionStrategy::Expression => self.complete_expression(input),

            CompletionStrategy::Type => {
                let types = self.caches.types.read().unwrap();
                let results = types.search(input.prefix, 1024);
                make_suggestions(results, "Structure", input.span_start, input.pos)
            }

            CompletionStrategy::Process => {
                let processes = self.caches.processes.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                processes
                    .iter()
                    .filter(|(name, pid)| {
                        name.to_lowercase().contains(&prefix_lower)
                            || pid.to_string().starts_with(input.prefix)
                    })
                    .map(|(name, pid)| Suggestion {
                        value: pid.to_string(),
                        description: Some(format!("{} (PID {})", name, pid)),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(input.span_start, input.pos),
                        append_whitespace: false,
                    display_override: None,
                    })
                    .collect()
            }

            CompletionStrategy::Thread => {
                let threads = self.caches.threads.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                threads
                    .iter()
                    .filter(|thread| {
                        thread
                            .tid
                            .is_some_and(|tid| tid.to_string().starts_with(input.prefix))
                            || format!("{:#x}", thread.ethread.0).starts_with(input.prefix)
                            || thread
                                .process_name
                                .as_deref()
                                .is_some_and(|name| name.to_lowercase().contains(&prefix_lower))
                    })
                    .map(|thread| {
                        let value = thread
                            .tid
                            .map(|tid| tid.to_string())
                            .unwrap_or_else(|| format!("{:#x}", thread.ethread.0));
                        let process = thread.process_name.as_deref().unwrap_or("unknown");
                        let tid = thread
                            .tid
                            .map(|tid| tid.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        Suggestion {
                            value,
                            description: Some(format!(
                                "{} TID {} ETHREAD {:#x}",
                                process, tid, thread.ethread.0
                            )),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(input.span_start, input.pos),
                            append_whitespace: false,
                        display_override: None,
                        }
                    })
                    .collect()
            }

            CompletionStrategy::Vcpu => {
                let vcpus = self.caches.vcpus.read().unwrap();
                vcpus
                    .iter()
                    .filter(|tid| tid.starts_with(input.prefix))
                    .map(|tid| Suggestion {
                        value: tid.clone(),
                        description: Some("vCPU".to_string()),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(input.span_start, input.pos),
                        append_whitespace: false,
                    display_override: None,
                    })
                    .collect()
            }

            CompletionStrategy::Breakpoint => {
                let breakpoints = self.caches.breakpoints.read().unwrap();
                breakpoints
                    .iter()
                    .filter(|(id, _, _, _)| id.to_string().starts_with(input.prefix))
                    .map(|(id, _, addr, symbol)| {
                        let sym_str = symbol.as_deref().unwrap_or("-");
                        Suggestion {
                            value: id.to_string(),
                            description: Some(format!("{} @ {:#x}", sym_str, addr.0)),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(input.span_start, input.pos),
                            append_whitespace: false,
                        display_override: None,
                        }
                    })
                    .collect()
            }

            CompletionStrategy::Driver => {
                let drivers = self.caches.drivers.read().unwrap();
                let prefix_lower = input.prefix.to_lowercase();
                drivers
                    .iter()
                    .filter(|driver| {
                        driver.name.to_lowercase().contains(&prefix_lower)
                            || format!("{:#x}", driver.object.0).starts_with(input.prefix)
                    })
                    .map(|driver| Suggestion {
                        value: format!("{:#x}", driver.object.0),
                        description: Some(format!(
                            "{} start={:#x}",
                            driver.name, driver.driver_start.0
                        )),
                        style: None,
                        extra: None,
                        match_indices: None,
                        span: Span::new(input.arg_start, input.pos),
                        append_whitespace: false,
                    display_override: None,
                    })
                    .collect()
            }

            CompletionStrategy::Alias => self.complete_aliases(input),
        }
    }

    fn complete_aliases(&self, input: CompletionInput<'_>) -> Vec<Suggestion> {
        let aliases = self.caches.aliases.read().unwrap();
        aliases
            .iter()
            .filter(|(name, _)| name.starts_with(input.prefix))
            .map(|(name, expansion)| Suggestion {
                value: name.clone(),
                description: Some(expansion.clone()),
                style: None,
                extra: None,
                match_indices: None,
                span: Span::new(input.span_start, input.pos),
                append_whitespace: false,
            display_override: None,
            })
            .collect()
    }

    fn complete_expression(&self, input: CompletionInput<'_>) -> Vec<Suggestion> {
        let preceding = input.preceding();
        if preceding.ends_with("$$") {
            return vec![];
        }
        if preceding.ends_with('$') {
            return self.complete_expression_variables(input);
        }
        if preceding.ends_with('@') {
            return self.complete_registers(input);
        }

        if preceding.ends_with('[') {
            return vec![];
        }
        if preceding.ends_with("->") || preceding.ends_with('!') {
            return self.complete_symbol(input, false);
        }

        let mut suggestions = Vec::new();
        if !input.prefix.is_empty() {
            append_unique(&mut suggestions, self.complete_registers(input));
        }
        if is_cast_completion_context(preceding) {
            append_unique(&mut suggestions, self.complete_cast_types(input));
        }
        append_unique(&mut suggestions, self.complete_symbol_names(input, 1024));
        suggestions
    }

    fn complete_symbol(
        &self,
        input: CompletionInput<'_>,
        suppress_after_operator: bool,
    ) -> Vec<Suggestion> {
        if input.ident_start > 0 {
            let preceding = input.preceding();

            if suppress_after_operator
                && (preceding.ends_with('+')
                    || preceding.ends_with('-')
                    || preceding.ends_with('['))
            {
                return vec![];
            }

            if let Some(expr_text) = preceding.strip_suffix("->") {
                if let Ok(expr) = Expr::parse(expr_text) {
                    let dtb = *self.caches.dtb.read().unwrap();
                    let fields = expr.complete_fields(&self.caches.symbol_store, dtb, input.prefix);
                    if !fields.is_empty() {
                        return make_suggestions(fields, "Field", input.span_start, input.pos);
                    }
                }
                return vec![];
            }

            if is_cast_completion_context(preceding) {
                let suggestions = self.complete_cast_types(input);
                if !suggestions.is_empty() {
                    return suggestions;
                }
            }

            // `module!<prefix>` -> complete symbols within that module
            if let Some(module_part) = preceding.strip_suffix('!') {
                let module = module_part
                    .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                if !module.is_empty() {
                    let dtb = *self.caches.dtb.read().unwrap();
                    let results = self.caches.symbol_store.search_symbols_in_module(
                        dtb,
                        module,
                        input.prefix,
                        1024,
                    );
                    return make_suggestions(results, "Symbol", input.span_start, input.pos);
                }
            }
        }

        self.complete_symbol_names(input, 1024)
    }

    fn complete_cast_types(&self, input: CompletionInput<'_>) -> Vec<Suggestion> {
        let types = self.caches.types.read().unwrap();
        let mut results = types.search(input.prefix, 512);
        if !input.prefix.starts_with('_') {
            for result in types.search(&format!("_{}", input.prefix), 512) {
                if !results.contains(&result) {
                    results.push(result);
                }
            }
        }
        make_suggestions(results, "Type", input.span_start, input.pos)
    }

    fn complete_symbol_names(&self, input: CompletionInput<'_>, limit: usize) -> Vec<Suggestion> {
        let symbols = self.caches.symbols.read().unwrap();
        let results = symbols.search(input.prefix, limit);
        make_suggestions(results, "Symbol", input.span_start, input.pos)
    }

    fn complete_expression_variables(&self, input: CompletionInput<'_>) -> Vec<Suggestion> {
        let variables = self.caches.expression_variables.read().unwrap();
        variables
            .iter()
            .filter(|(name, _)| completion_name_matches(name, input.prefix))
            .map(|(name, kind)| Suggestion {
                value: name.clone(),
                description: Some((*kind).to_string()),
                style: None,
                extra: None,
                match_indices: None,
                span: Span::new(input.span_start, input.pos),
                append_whitespace: false,
            display_override: None,
            })
            .collect()
    }

    fn complete_registers(&self, input: CompletionInput<'_>) -> Vec<Suggestion> {
        self.caches
            .registers
            .iter()
            .filter(|name| completion_name_matches(name, input.prefix))
            .map(|name| Suggestion {
                value: name.clone(),
                description: Some("Register".to_string()),
                style: None,
                extra: None,
                match_indices: None,
                span: Span::new(input.span_start, input.pos),
                append_whitespace: false,
            display_override: None,
            })
            .collect()
    }
}

fn completion_name_matches(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn append_unique(suggestions: &mut Vec<Suggestion>, additions: Vec<Suggestion>) {
    for suggestion in additions {
        if !suggestions.iter().any(|s| s.value == suggestion.value) {
            suggestions.push(suggestion);
        }
    }
}

fn is_cast_completion_context(preceding: &str) -> bool {
    let Some(before_paren) = preceding.strip_suffix('(') else {
        return false;
    };
    !before_paren.trim_end().ends_with("poi")
}

fn infer_alias_completion_strategy(
    expansion: &str,
    alias_arg_index: usize,
    user_cmds: &UserCommandCache,
) -> CompletionStrategy {
    let Ok(commands) = split_command_list(expansion) else {
        return CompletionStrategy::None;
    };
    let mut strategy = None;
    for command in commands {
        let Some(candidate) =
            infer_alias_command_completion_strategy(command, alias_arg_index, user_cmds)
        else {
            continue;
        };
        if !merge_completion_strategy(&mut strategy, candidate) {
            return CompletionStrategy::None;
        }
    }
    strategy.unwrap_or(CompletionStrategy::None)
}

fn infer_alias_command_completion_strategy(
    command: &str,
    alias_arg_index: usize,
    user_cmds: &UserCommandCache,
) -> Option<CompletionStrategy> {
    let Ok(Some(parsed)) = parse_command(command) else {
        return None;
    };

    if let Some(spec) = command_registry().get(parsed.name) {
        return match spec.style {
            CommandStyle::StructuredArgs => {
                infer_structured_alias_completion(&parsed, spec.completion, alias_arg_index)
            }
            CommandStyle::RawTail | CommandStyle::ExpressionTail => {
                alias_placeholder_matches(parsed.raw_tail, alias_arg_index)
                    .then(|| spec.completion.strategy_for_arg(0))
            }
        };
    }

    let (_, _, strategies) = user_cmds.iter().find(|(name, _, _)| name == parsed.name)?;
    let Ok(invocation) = parsed.invocation(CommandStyle::StructuredArgs) else {
        return None;
    };
    let mut strategy = None;
    for (index, arg) in invocation.argv.iter().enumerate() {
        if !alias_placeholder_matches(arg.as_ref(), alias_arg_index) {
            continue;
        }
        let candidate = strategies
            .get(index)
            .copied()
            .unwrap_or(CompletionStrategy::None);
        if !merge_completion_strategy(&mut strategy, candidate) {
            return Some(CompletionStrategy::None);
        }
    }
    strategy
}

fn infer_structured_alias_completion(
    parsed: &ParsedCommand<'_>,
    completion: CompletionSpec,
    alias_arg_index: usize,
) -> Option<CompletionStrategy> {
    let Ok(invocation) = parsed.invocation(CommandStyle::StructuredArgs) else {
        return None;
    };
    let mut strategy = None;
    for (index, arg) in invocation.argv.iter().enumerate() {
        if !alias_placeholder_matches(arg.as_ref(), alias_arg_index) {
            continue;
        }
        let candidate = completion.strategy_for_arg(index);
        if !merge_completion_strategy(&mut strategy, candidate) {
            return Some(CompletionStrategy::None);
        }
    }
    strategy
}

fn merge_completion_strategy(
    strategy: &mut Option<CompletionStrategy>,
    candidate: CompletionStrategy,
) -> bool {
    match *strategy {
        Some(existing) => existing == candidate,
        None => {
            *strategy = Some(candidate);
            true
        }
    }
}

fn alias_placeholder_matches(text: &str, alias_arg_index: usize) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return false;
        };
        let key = &after_start[..end];
        if key == "*" {
            return true;
        }
        if key
            .parse::<usize>()
            .ok()
            .and_then(|index| index.checked_sub(1))
            == Some(alias_arg_index)
        {
            return true;
        }
        rest = &after_start[end + 1..];
    }
    false
}

pub struct TrackingHighlighter {
    pub had_content: Arc<AtomicBool>,
}

impl Highlighter for TrackingHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        self.had_content.store(!line.is_empty(), Ordering::Relaxed);

        let mut styled = StyledText::new();
        styled.push((Style::new(), line.to_string()));
        styled
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use super::*;
    use crate::symbols::{SymbolIndex, SymbolStore};
    use crate::target::DriverObjectInfo;
    use crate::types::VirtAddr;

    fn completer() -> MyCompleter {
        MyCompleter {
            caches: ReplCaches {
                symbols: Arc::new(RwLock::new(SymbolIndex::default())),
                types: Arc::new(RwLock::new(SymbolIndex::default())),
                symbol_store: Arc::new(SymbolStore::new()),
                dtb: Arc::new(RwLock::new(0)),
                processes: Arc::new(RwLock::new(Vec::new())),
                threads: Arc::new(RwLock::new(Vec::new())),
                vcpus: Arc::new(RwLock::new(Vec::new())),
                breakpoints: Arc::new(RwLock::new(Vec::new())),
                drivers: Arc::new(RwLock::new(Vec::new())),
                registers: Arc::new(vec!["rax".into(), "rip".into()]),
                expression_variables: Arc::new(RwLock::new(vec![
                    ("0".into(), "Result"),
                    ("foo".into(), "Variable"),
                    ("thread".into(), "Builtin"),
                ])),
                user_commands: Arc::new(RwLock::new(Vec::new())),
                aliases: Arc::new(RwLock::new(Vec::new())),
            },
        }
    }

    fn add_alias(completer: &mut MyCompleter, name: &str, expansion: &str) {
        completer
            .caches
            .aliases
            .write()
            .unwrap()
            .push((name.to_string(), expansion.to_string()));
    }

    fn values(suggestions: Vec<Suggestion>) -> Vec<String> {
        suggestions
            .into_iter()
            .map(|suggestion| suggestion.value)
            .collect()
    }

    #[test]
    fn expression_completion_uses_dollar_for_debugger_variables() {
        let mut completer = completer();

        assert_eq!(values(completer.complete("ev $t", 5)), vec!["thread"]);
        assert!(completer.complete("ev $$", 5).is_empty());
    }

    #[test]
    fn expression_completion_uses_at_for_registers() {
        let mut completer = completer();

        assert_eq!(values(completer.complete("ev @r", 5)), vec!["rax", "rip"]);
    }

    #[test]
    fn expression_completion_includes_bare_registers() {
        let mut completer = completer();

        assert_eq!(values(completer.complete("ev r", 4)), vec!["rax", "rip"]);
    }

    #[test]
    fn expression_completion_includes_registers_in_groups() {
        let mut completer = completer();

        assert_eq!(values(completer.complete("ev (r", 5)), vec!["rax", "rip"]);
    }

    #[test]
    fn expression_completion_stays_empty_in_numeric_index() {
        let mut completer = completer();

        assert!(completer.complete("ev addr[r", 9).is_empty());
    }

    #[test]
    fn symbol_completion_does_not_use_debugger_variables() {
        let mut completer = completer();

        assert!(completer.complete("x $t", 4).is_empty());
    }

    #[test]
    fn unalias_completes_alias_names() {
        let mut completer = completer();
        add_alias(&mut completer, "ubp", "bp ${1}; g");

        assert_eq!(values(completer.complete("unalias u", 9)), vec!["ubp"]);
    }

    #[test]
    fn alias_completion_infers_placeholder_strategy_from_target_command() {
        let mut completer = completer();
        add_alias(&mut completer, "ubp", "bp ${1}; g");

        assert_eq!(values(completer.complete("ubp r", 5)), vec!["rax", "rip"]);
    }

    #[test]
    fn alias_completion_infers_star_placeholder_strategy() {
        let mut completer = completer();
        add_alias(&mut completer, "bpa", "bp ${*}; g");

        assert_eq!(values(completer.complete("bpa r", 5)), vec!["rax", "rip"]);
    }

    #[test]
    fn alias_completion_uses_target_command_arg_index() {
        let mut completer = completer();
        add_alias(&mut completer, "cbc", "bc ${1}");
        completer
            .caches
            .breakpoints
            .write()
            .unwrap()
            .push((12, true, VirtAddr(0x1234), Some("nt!Foo".into())));

        assert_eq!(values(completer.complete("cbc 1", 5)), vec!["12"]);
    }

    #[test]
    fn alias_completion_ignores_conflicting_placeholder_strategies() {
        let user_cmds = Vec::new();

        assert_eq!(
            infer_alias_completion_strategy("bp ${1}; bc ${1}", 0, &user_cmds),
            CompletionStrategy::None
        );
    }

    #[test]
    fn completion_span_starts_after_any_whitespace_separator() {
        let mut completer = completer();
        completer
            .caches
            .drivers
            .write()
            .unwrap()
            .push(DriverObjectInfo {
                name: "FooDriver".into(),
                object: VirtAddr(0x1234),
                driver_start: VirtAddr(0x1000),
                driver_size: 0x100,
                device_object: VirtAddr(0),
                driver_unload: VirtAddr(0),
            });

        let suggestions = completer.complete("drvobj\tfoo", 10);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].span, Span::new(7, 10));
    }
}
