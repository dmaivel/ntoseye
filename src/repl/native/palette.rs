//! The command palette, F1 at the prompt: Tern's picker over the commands
//! and recent lines, the symbol and type indexes and the processes, in a
//! screen surface of its own so the pane is left as it was. It hands back
//! the line to go on editing.

use std::cmp::Reverse;
use std::sync::{Arc, RwLock};

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use tern_sdk::keys::Key;
use tern_sdk::ui::{
    self, BadgeSpec, Icon, OrderEntry, PickerAction, PickerItem, PickerPreview, PickerSize,
    PickerTab,
};
use tern_sdk::{Input, Node, Options, Session, SurfaceOptions, View};

use super::ROLE;
use crate::symbols::SymbolIndex;

/// What the palette offers, gathered when it opens.
pub struct Catalog {
    /// Earlier lines, newest first, each once.
    pub recent: Vec<String>,
    pub commands: Vec<CommandEntry>,
    pub symbols: Arc<RwLock<SymbolIndex>>,
    pub types: Arc<RwLock<SymbolIndex>>,
    /// Image name and PID.
    pub processes: Vec<(String, u64)>,
}

/// A command the palette lists: a built-in, a script's command or an alias.
pub struct CommandEntry {
    pub name: String,
    /// Its other names.
    pub aliases: Vec<String>,
    pub summary: String,
    /// The usage line, or what an alias expands to.
    pub usage: String,
    pub details: Option<String>,
    /// Whether it takes arguments, so picking it leaves a space after it.
    pub takes_args: bool,
}

/// The palette's tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Commands,
    Symbols,
    Types,
    Processes,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Commands, Self::Symbols, Self::Types, Self::Processes];

    fn id(self) -> &'static str {
        match self {
            Self::Commands => "commands",
            Self::Symbols => "symbols",
            Self::Types => "types",
            Self::Processes => "processes",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Commands => "Commands",
            Self::Symbols => "Symbols",
            Self::Types => "Types",
            Self::Processes => "Processes",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Commands => "commands",
            Self::Symbols => "symbols",
            Self::Types => "types",
            Self::Processes => "processes",
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tab| tab.id() == id)
    }
}

/// What the picker's pointer gestures report.
#[derive(Clone)]
enum Msg {
    Select(String),
    Activate(String),
    Close,
    Insert,
    Tab(String),
}

/// How many recent lines the Commands tab shows: before the commands with
/// nothing typed, and after them as matches.
const RECENT: usize = 8;
const RECENT_MATCHES: usize = 5;
/// How many matches an index search shows.
const SEARCH_LIMIT: usize = 200;
/// How far Page Up and Page Down move.
const PAGE: isize = 10;

/// Show the palette over the pane on `tab`, for the line being edited,
/// `buffer`: the line to go on editing when something was picked, `None`
/// when the palette was closed or Tern can't show it.
pub fn run(catalog: &Catalog, buffer: &str, tab: Tab) -> Option<String> {
    let options = Options::new()
        .app("ntoseye")
        .version(env!("CARGO_PKG_VERSION"))
        .bracketed_paste(false)
        .kitty_keyboard(false);
    let mut session = Session::<Msg>::connect(options).ok().flatten()?;
    let picked = pick(&mut session, catalog, buffer, tab);
    // Restores the terminal for the line editor whatever happened.
    let _ = session.close();
    picked
}

fn pick(session: &mut Session<Msg>, catalog: &Catalog, buffer: &str, tab: Tab) -> Option<String> {
    let surface = session
        .open(
            SurfaceOptions::screen()
                .role(format!("{ROLE}.palette"))
                .keep(false),
        )
        .ok()?;
    let mut palette = Palette::new(catalog, buffer, tab);
    loop {
        session.render(surface, palette.view()).ok()?;
        let outcome = match session.next(None).ok()?? {
            Input::Key(key) => palette.key(&key),
            Input::Msg(msg, _) => palette.message(msg),
            Input::Event(_) => Outcome::Continue,
        };
        match outcome {
            Outcome::Continue => {}
            Outcome::Close => return None,
            Outcome::Pick => return palette.picked(),
        }
    }
}

enum Outcome {
    Continue,
    Close,
    Pick,
}

/// A row: what it shows and what picking it does.
struct Row {
    id: String,
    group: Option<&'static str>,
    label: String,
    detail: Option<String>,
    badges: Vec<String>,
    hits: Vec<[usize; 2]>,
    icon: Option<Icon>,
    pick: Pick,
}

enum Pick {
    /// The line becomes this.
    Line(String),
    /// The command at this index of the catalog's.
    Command(usize),
    /// This replaces the word being typed.
    Word(String),
}

struct Palette<'a> {
    catalog: &'a Catalog,
    /// The line up to the word being typed, which the query replaces.
    head: String,
    tab: Tab,
    query: String,
    rows: Vec<Row>,
    selected: usize,
    matcher: Matcher,
}

impl<'a> Palette<'a> {
    fn new(catalog: &'a Catalog, buffer: &str, tab: Tab) -> Self {
        let buffer = buffer.trim_start();
        let (head, word) = match buffer.rfind(char::is_whitespace) {
            Some(at) => buffer.split_at(at + 1),
            None => ("", buffer),
        };
        let mut palette = Self {
            catalog,
            head: head.to_owned(),
            tab,
            query: word.to_owned(),
            rows: Vec::new(),
            selected: 0,
            matcher: Matcher::new(Config::DEFAULT),
        };
        palette.refresh();
        palette
    }

    fn key(&mut self, key: &Key) -> Outcome {
        if key.is("escape") || key.is("ctrl+c") || key.is("ctrl+g") {
            return Outcome::Close;
        }
        if key.is("enter") {
            return Outcome::Pick;
        }
        if key.is("up") || key.is("ctrl+p") {
            self.move_by(-1);
        } else if key.is("down") || key.is("ctrl+n") {
            self.move_by(1);
        } else if key.is("page_up") {
            self.move_by(-PAGE);
        } else if key.is("page_down") {
            self.move_by(PAGE);
        } else if key.is("tab") {
            self.switch_by(1);
        } else if key.is("shift+tab") || key.name == "backtab" {
            self.switch_by(-1);
        } else if key.is("backspace") {
            self.query.pop();
            self.refresh();
        } else if key.is("ctrl+u") {
            self.query.clear();
            self.refresh();
        } else if key.is("ctrl+w") || key.is("alt+backspace") {
            let kept = self.query.trim_end().rfind(' ').map_or(0, |at| at + 1);
            self.query.truncate(kept);
            self.refresh();
        } else if key.name == "paste" {
            let text = key.text.as_deref().unwrap_or_default();
            self.query.push_str(text.lines().next().unwrap_or_default());
            self.refresh();
        } else if let Some(text) = key.typed() {
            self.query.push_str(text);
            self.refresh();
        }
        Outcome::Continue
    }

    fn message(&mut self, msg: Msg) -> Outcome {
        match msg {
            Msg::Select(id) => self.select(&id),
            Msg::Activate(id) => {
                self.select(&id);
                return Outcome::Pick;
            }
            Msg::Close => return Outcome::Close,
            Msg::Insert => return Outcome::Pick,
            Msg::Tab(id) => {
                if let Some(tab) = Tab::from_id(&id) {
                    self.switch(tab);
                }
            }
        }
        Outcome::Continue
    }

    /// The line to go on editing, from the selected row.
    fn picked(&self) -> Option<String> {
        let row = self.rows.get(self.selected)?;
        Some(match &row.pick {
            Pick::Line(line) => line.clone(),
            Pick::Command(index) => {
                let command = &self.catalog.commands[*index];
                let space = if command.takes_args { " " } else { "" };
                format!("{}{space}", command.name)
            }
            Pick::Word(word) => format!("{}{word}", self.head),
        })
    }

    fn select(&mut self, id: &str) {
        if let Some(index) = self.rows.iter().position(|row| row.id == id) {
            self.selected = index;
        }
    }

    fn move_by(&mut self, by: isize) {
        let last = self.rows.len().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(by).min(last);
    }

    fn switch_by(&mut self, by: isize) {
        let at = Tab::ALL
            .iter()
            .position(|tab| *tab == self.tab)
            .unwrap_or(0);
        let next = (at as isize + by).rem_euclid(Tab::ALL.len() as isize) as usize;
        self.switch(Tab::ALL[next]);
    }

    fn switch(&mut self, tab: Tab) {
        self.tab = tab;
        self.refresh();
    }

    /// Rank the tab's rows against the query, selecting the first.
    fn refresh(&mut self) {
        let pattern = Pattern::parse(&self.query, CaseMatching::Smart, Normalization::Smart);
        self.rows = match self.tab {
            Tab::Commands => self.command_rows(&pattern),
            Tab::Symbols => self.index_rows(&pattern, &self.catalog.symbols.clone(), "s"),
            Tab::Types => self.index_rows(&pattern, &self.catalog.types.clone(), "t"),
            Tab::Processes => self.process_rows(&pattern),
        };
        self.selected = 0;
    }

    /// With nothing typed, the recent lines and then the commands in their
    /// order. With a query, the commands first, best match first and a
    /// match on the name before one on what the command does, then the
    /// recent lines that match.
    fn command_rows(&mut self, pattern: &Pattern) -> Vec<Row> {
        let typed = !self.query.is_empty();
        let mut recent: Vec<(u32, Row)> = Vec::new();
        for (index, line) in self.catalog.recent.iter().enumerate() {
            if let Some((score, hits)) = self.score(pattern, line) {
                recent.push((
                    score,
                    Row {
                        id: format!("h{index}"),
                        group: Some("Recent"),
                        label: line.clone(),
                        detail: None,
                        badges: Vec::new(),
                        hits,
                        icon: Some(Icon::History),
                        pick: Pick::Line(line.clone()),
                    },
                ));
            }
        }
        if typed {
            recent.sort_by_key(|(score, _)| Reverse(*score));
            recent.truncate(RECENT_MATCHES);
        } else {
            recent.truncate(RECENT);
        }

        let mut commands: Vec<((u8, u32), Row)> = Vec::new();
        for (index, command) in self.catalog.commands.iter().enumerate() {
            let named = self
                .score(pattern, &command.name)
                .map(|(score, hits)| ((0, score), hits));
            let rank = named.or_else(|| {
                command
                    .aliases
                    .iter()
                    .chain([&command.summary])
                    .filter_map(|text| self.score(pattern, text))
                    .map(|(score, _)| score)
                    .max()
                    .map(|score| ((1, score), Vec::new()))
            });
            let Some((rank, hits)) = rank else {
                continue;
            };
            commands.push((
                rank,
                Row {
                    id: format!("c{index}"),
                    group: Some("Commands"),
                    label: command.name.clone(),
                    detail: Some(command.summary.clone()),
                    badges: command.aliases.iter().take(3).cloned().collect(),
                    hits,
                    icon: None,
                    pick: Pick::Command(index),
                },
            ));
        }
        if typed {
            commands.sort_by(|left, right| {
                let ((tier, score), row) = left;
                let ((other_tier, other_score), other) = right;
                tier.cmp(other_tier)
                    .then(other_score.cmp(score))
                    .then(row.label.len().cmp(&other.label.len()))
            });
        }
        let recent = recent.into_iter().map(|(_, row)| row);
        let commands = commands.into_iter().map(|(_, row)| row);
        if typed {
            commands.chain(recent).collect()
        } else {
            recent.chain(commands).collect()
        }
    }

    /// Names from a symbol index, as `x` searches it: nothing until
    /// something is typed.
    fn index_rows(
        &mut self,
        pattern: &Pattern,
        index: &RwLock<SymbolIndex>,
        prefix: &str,
    ) -> Vec<Row> {
        if self.query.is_empty() {
            return Vec::new();
        }
        let names = index.read().unwrap().search(&self.query, SEARCH_LIMIT);
        names
            .into_iter()
            .map(|name| {
                let hits = self
                    .score(pattern, &name)
                    .map(|(_, hits)| hits)
                    .unwrap_or_default();
                Row {
                    id: format!("{prefix}{name}"),
                    group: None,
                    detail: None,
                    badges: Vec::new(),
                    hits,
                    icon: None,
                    pick: Pick::Word(name.clone()),
                    label: name,
                }
            })
            .collect()
    }

    /// The processes by name; with no command typed, picking one switches
    /// to it.
    fn process_rows(&mut self, pattern: &Pattern) -> Vec<Row> {
        let switch = self.head.trim().is_empty();
        let mut rows: Vec<(u32, Row)> = Vec::new();
        for (name, pid) in &self.catalog.processes {
            let Some((score, hits)) = self.score(pattern, name) else {
                continue;
            };
            let pick = if switch {
                Pick::Line(format!(".process /p {pid}"))
            } else {
                Pick::Word(pid.to_string())
            };
            rows.push((
                score,
                Row {
                    id: format!("p{pid}"),
                    group: None,
                    label: name.clone(),
                    detail: Some(format!("pid {pid}")),
                    badges: Vec::new(),
                    hits,
                    icon: None,
                    pick,
                },
            ));
        }
        if !self.query.is_empty() {
            rows.sort_by_key(|(score, _)| Reverse(*score));
        }
        rows.into_iter().map(|(_, row)| row).collect()
    }

    /// How well `text` matches, and where, as UTF-16 ranges.
    fn score(&mut self, pattern: &Pattern, text: &str) -> Option<(u32, Vec<[usize; 2]>)> {
        let mut chars = Vec::new();
        let mut indices = Vec::new();
        let score = pattern.indices(
            Utf32Str::new(text, &mut chars),
            &mut self.matcher,
            &mut indices,
        )?;
        indices.sort_unstable();
        indices.dedup();
        Some((score, utf16_ranges(text, &indices)))
    }

    fn view(&self) -> View<Msg> {
        let mut items = Vec::with_capacity(self.rows.len());
        let mut order = Vec::with_capacity(self.rows.len() + 2);
        let mut group = None;
        for row in &self.rows {
            if row.group != group {
                if let Some(label) = row.group {
                    order.push(OrderEntry::Group {
                        group: label.to_lowercase(),
                        label: label.to_owned(),
                        count: None,
                    });
                }
                group = row.group;
            }
            order.push(OrderEntry::Item(row.id.clone()));
            items.push(item(row));
        }
        let tabs: Vec<PickerTab> = Tab::ALL
            .into_iter()
            .map(|tab| PickerTab {
                id: tab.id().to_owned(),
                label: tab.label().to_owned(),
                count: None,
            })
            .collect();
        let empty = match self.tab {
            Tab::Symbols | Tab::Types if self.query.is_empty() => {
                format!("Type to search the {}", self.tab.noun())
            }
            _ => format!("No {} match", self.tab.noun()),
        };
        let mut picker = ui::picker()
            .size(PickerSize::Md)
            .preview(match self.tab {
                Tab::Commands => PickerPreview::Below,
                _ => PickerPreview::None,
            })
            .title("ntoseye")
            .icon(Icon::Terminal)
            .query(self.query.clone())
            .placeholder(format!("Search {}", self.tab.noun()))
            .noun(self.tab.noun())
            .empty(empty)
            .items(items)
            .order(order)
            .tabs(tabs)
            .tab(self.tab.id().to_owned())
            .actions(vec![
                PickerAction {
                    id: "close".into(),
                    label: Some("Close".into()),
                    keys: vec!["esc".into()],
                    ..PickerAction::default()
                },
                PickerAction {
                    id: "insert".into(),
                    label: Some("Insert".into()),
                    keys: vec!["enter".into()],
                    primary: Some(true),
                    ..PickerAction::default()
                },
            ])
            .on_select(|item| Msg::Select(item.to_owned()))
            .on_activate(|item| Msg::Activate(item.to_owned()))
            .on_action("close", Msg::Close)
            .on_action("insert", Msg::Insert)
            .on_action_with("tab", |action| {
                Msg::Tab(action.value.clone().unwrap_or_default())
            });
        if let Some(row) = self.rows.get(self.selected) {
            picker = picker.selected(row.id.clone()).children(self.preview(row));
        }
        View::new().layer([Node::from(picker)])
    }

    /// A command's help, or a recent line, under the list.
    fn preview(&self, row: &Row) -> Vec<Node<Msg>> {
        match &row.pick {
            Pick::Command(index) => {
                let command = &self.catalog.commands[*index];
                let mut nodes = vec![
                    Node::from(ui::md(command.summary.as_str())),
                    Node::from(ui::code(command.usage.as_str())),
                ];
                if let Some(details) = &command.details {
                    nodes.push(Node::from(ui::md(details.as_str())));
                }
                nodes
            }
            Pick::Line(line) => vec![Node::from(ui::code(line.as_str()))],
            Pick::Word(_) => Vec::new(),
        }
    }
}

fn item(row: &Row) -> PickerItem {
    let mut item = PickerItem::new(row.id.clone(), row.label.as_str());
    item.detail = row.detail.as_deref().map(Into::into);
    item.icon = row.icon.clone();
    item.mono = Some(true);
    item.hits = row.hits.clone();
    item.badges = row
        .badges
        .iter()
        .map(|text| BadgeSpec {
            text: text.clone(),
            ..BadgeSpec::default()
        })
        .collect();
    item
}

/// Character `indices` into `text` as merged `[from, to)` UTF-16 ranges.
fn utf16_ranges(text: &str, indices: &[u32]) -> Vec<[usize; 2]> {
    let mut starts = Vec::new();
    let mut at = 0;
    for c in text.chars() {
        starts.push((at, c.len_utf16()));
        at += c.len_utf16();
    }
    let mut ranges: Vec<[usize; 2]> = Vec::new();
    for &index in indices {
        let Some(&(from, len)) = starts.get(index as usize) else {
            continue;
        };
        match ranges.last_mut() {
            Some(last) if last[1] == from => last[1] = from + len,
            _ => ranges.push([from, from + len]),
        }
    }
    ranges
}
