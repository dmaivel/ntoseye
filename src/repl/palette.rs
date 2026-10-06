//! The command palette's REPL side: what it offers, which tab it opens on,
//! and putting the picked line back in the prompt. Tern draws it
//! ([`native::palette`]); F1 opens it, bound only in Tern.

use reedline::{EditCommand, Reedline, SearchDirection, SearchQuery};

use super::native::palette::{self, Catalog, CommandEntry, Tab};
use super::{CompletionStrategy, ReplState, command_registry};

/// The host command F1 sends the REPL loop.
pub const PALETTE_COMMAND: &str = "palette";

/// How many distinct earlier lines the palette ranks.
pub const RECENT_LINES: usize = 1000;

impl ReplState<'_> {
    /// Show the palette for the line being edited, and put back what was
    /// picked. Closing it leaves the line as it was.
    pub fn open_palette(&mut self, line_editor: &mut Reedline) {
        let buffer = line_editor.current_buffer_contents().to_owned();
        let catalog = self.palette_catalog(recent_lines(line_editor));
        if let Some(line) = palette::run(catalog, &buffer, initial_tab(&buffer)) {
            line_editor.run_edit_commands(&[EditCommand::Clear, EditCommand::InsertString(line)]);
        }
    }

    /// What the palette offers, with `recent` as the recent lines.
    pub fn palette_catalog(&self, recent: Vec<String>) -> Catalog {
        Catalog {
            recent,
            commands: self.palette_commands(),
            symbols: self.caches.symbols.clone(),
            types: self.caches.types.clone(),
            processes: self
                .ctx
                .target
                .matching_processes(None)
                .map(|processes| {
                    processes
                        .into_iter()
                        .map(|process| (process.name, process.pid))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The built-in commands by their first name, then the scripts'
    /// commands and the aliases.
    fn palette_commands(&self) -> Vec<CommandEntry> {
        let mut commands: Vec<CommandEntry> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (_, spec) in command_registry().command_names() {
            if !seen.insert(spec.names[0]) {
                continue;
            }
            commands.push(CommandEntry {
                name: spec.names[0].to_owned(),
                aliases: spec.names[1..]
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                summary: spec.summary.to_owned(),
                usage: spec.usage.to_owned(),
                details: spec.details.map(str::to_owned),
                takes_args: spec.usage.trim().contains(char::is_whitespace),
            });
        }
        commands.sort_by(|left, right| left.name.cmp(&right.name));
        for (name, help, args) in self.caches.user_commands.read().unwrap().iter() {
            commands.push(CommandEntry {
                name: name.clone(),
                aliases: Vec::new(),
                summary: help.lines().next().unwrap_or_default().to_owned(),
                usage: name.clone(),
                details: None,
                takes_args: !args.is_empty(),
            });
        }
        for (name, expansion) in self.caches.aliases.read().unwrap().iter() {
            commands.push(CommandEntry {
                name: name.clone(),
                aliases: Vec::new(),
                summary: format!("alias for `{expansion}`"),
                usage: expansion.clone(),
                details: None,
                takes_args: expansion.contains('$'),
            });
        }
        commands
    }
}

/// The line editor's history, newest first, each line once.
fn recent_lines(line_editor: &Reedline) -> Vec<String> {
    let items = line_editor
        .history()
        .search(SearchQuery::everything(SearchDirection::Backward, None))
        .unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .map(|item| item.command_line)
        .filter(|line| !line.trim().is_empty() && seen.insert(line.clone()))
        .take(RECENT_LINES)
        .collect()
}

/// The tab for what is being typed: commands for the command word, and
/// for an argument what that argument of the command completes as.
pub fn initial_tab(buffer: &str) -> Tab {
    let buffer = buffer.trim_start();
    let words: Vec<&str> = buffer.split_whitespace().collect();
    if !buffer.contains(char::is_whitespace) {
        return Tab::Commands;
    }
    let argument = if buffer.ends_with(char::is_whitespace) {
        words.len() - 1
    } else {
        words.len() - 2
    };
    let strategy = command_registry()
        .get(words[0])
        .map(|spec| spec.completion.strategy_for_arg(argument));
    match strategy {
        Some(CompletionStrategy::Process) => Tab::Processes,
        Some(CompletionStrategy::Type) => Tab::Types,
        _ => Tab::Symbols,
    }
}
