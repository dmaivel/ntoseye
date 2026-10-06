//! The Tern-native prompt. In Tern the line is edited in Tern's own input
//! field instead of by the line editor: a live flow surface holds
//! it in its dock, sticky at the pane's bottom, under a status bar, with the
//! completions in a popup at the caret and the palette over the pane. The
//! surface closes before the command runs, so what the command shows lands
//! in the scrollback exactly as it does after the line editor.

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::time::Duration;

use owo_colors::OwoColorize;
use reedline::{Completer, History, HistoryItem, SearchDirection, SearchQuery, Suggestion};
use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Anchor, Decor, Icon, OverlaySize, Side};
use tern_sdk::wire::{self, Edit, Event};
use tern_sdk::{Input, Node, Session, Surface, SurfaceOptions, View};

use super::command::{
    command_registry, is_comment, parse_command, script_file_token, split_command_list,
};
use super::completion::ReplCaches;
use super::native::palette::{Outcome, Palette, Tab};
use super::native::{self, DIM, MNEMONIC, MUTED, NUMBER, REGISTER, STRING, SYMBOL, span};
use super::palette::{RECENT_LINES, initial_tab};
use super::{
    CustomPrompt, MyCompleter, NATIVE_PROMPT, ReplState, TargetLoan, termination_requested,
};
use crate::output::prompting;

/// The input's id: key `ed` in the dock.
const EDITOR: &str = "dock.ed";
/// The surface's id: one at a time, removed before the command runs.
const SURFACE: &str = "ntoseye.prompt";
/// How many completions the popup lists.
const POPUP_LIMIT: usize = 100;
/// How many rows the popup shows before it scrolls.
const POPUP_ROWS: u32 = 10;
/// How many undo steps a line keeps.
const UNDO_LIMIT: usize = 200;
/// How often the prompt looks for a termination signal while it waits: the
/// SDK's read retries an interrupted poll.
const TERMINATION_POLL: Duration = Duration::from_millis(200);

/// What reading a line gave.
pub enum Read {
    /// A line to run, already echoed into the scrollback.
    Line(String),
    /// Ctrl+C at an empty line.
    Interrupt,
    /// Ctrl+D at an empty line, or a termination signal.
    Quit,
    /// Ctrl+L: the screen was cleared, read again.
    Clear,
    /// F2: open the browser, then go on editing the line.
    Browse,
    /// Tern didn't answer: use the line editor.
    Unavailable,
}

/// The prompt's state across lines.
pub struct TernPrompt {
    /// The earlier lines, oldest first.
    history: Vec<String>,
    /// Keys typed after the Enter that ended a line, for the next one: the
    /// session that read them closes before the command runs.
    ahead: VecDeque<Key>,
    /// The line and caret F2 left, to go on editing after the browser.
    kept: Option<(String, usize)>,
}

/// What reading a line consults.
struct Ctx<'c, 'r> {
    state: &'c ReplState<'r>,
    completer: &'c mut MyCompleter,
    loan: &'c TargetLoan,
}

impl TernPrompt {
    pub fn new(history: &dyn History) -> Self {
        let history = history
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.command_line)
            .collect();
        Self {
            history,
            ahead: VecDeque::new(),
            kept: None,
        }
    }

    /// Read one line in Tern. A line to run is echoed into the scrollback
    /// with the prompt, as the line editor leaves it, and saved to
    /// `history` unless it starts with a space.
    pub fn read(
        &mut self,
        state: &ReplState,
        completer: &mut MyCompleter,
        loan: &TargetLoan,
        history: &mut dyn History,
    ) -> Read {
        let features = [
            wire::feature::EDIT,
            wire::feature::UNDO,
            wire::feature::SEND,
        ];
        // A paste arrives whole, to be joined into one line rather than run
        // line by line as typed.
        let Some(mut session) = native::connect_with::<()>(&features, true) else {
            return Read::Unavailable;
        };
        // Tern's field draws the caret; the grid's would blink on the
        // surface's empty anchor row.
        write_now(b"\x1b[?25l");
        // The termination bridge must not swap stdin under the session: the
        // loop below polls for it, and the close needs the real terminal to
        // drain Tern's answers.
        NATIVE_PROMPT.store(true, Ordering::SeqCst);
        let mut ctx = Ctx {
            state,
            completer,
            loan,
        };
        let read = prompting(|| self.run(&mut session, &mut ctx));
        NATIVE_PROMPT.store(false, Ordering::SeqCst);
        let _ = session.close();
        write_now(b"\x1b[?25h");
        let Some(read) = read else {
            return Read::Unavailable;
        };
        match &read {
            Read::Line(line) => {
                // The removed surface leaves its anchor row empty, with the
                // cursor under it: the echo takes that row.
                write_now(b"\x1b[A\r");
                let prompt = CustomPrompt::new(state.ctx.backend.name(), &state.ctx.current_thread);
                let trimmed = line.trim_start();
                outln!(
                    "{} {}",
                    prompt.left,
                    colored(trimmed, &ctx.completer.caches)
                );
                if !line.starts_with(' ') {
                    let _ = history.save(HistoryItem::from_command_line(trimmed.to_owned()));
                    let _ = history.sync();
                    self.history.push(trimmed.to_owned());
                }
            }
            Read::Clear => write_now(b"\x1b[H\x1b[2J\x1b[3J"),
            _ => {}
        }
        read
    }

    fn run(&mut self, session: &mut Session<()>, ctx: &mut Ctx) -> Option<Read> {
        let surface = session
            .open(
                SurfaceOptions::flow()
                    .id(SURFACE)
                    .role("ntoseye.prompt")
                    .keep(false),
            )
            .ok()?;
        let _ = session.stylesheet(surface, "ntoseye", Some(native::STYLESHEET));
        let ahead = &mut self.ahead;
        let mut line = Line::new(&self.history);
        if let Some((draft, cursor)) = self.kept.take() {
            line.draft = draft;
            line.cursor = cursor;
        }
        let mut focused = false;
        let read = loop {
            session.render(surface, line.view(ctx)).ok()?;
            // The field holds the caret except while the palette is open.
            if line.palette.is_some() {
                focused = false;
            } else if !focused {
                let _ = session.focus(surface, Some(EDITOR));
                focused = true;
            }
            let input = match ahead.pop_front() {
                Some(key) => Input::Key(key),
                None => match next_input(session) {
                    Some(input) => input,
                    None => break Read::Quit,
                },
            };
            // A click in the field when it lost the caret.
            if matches!(input, Input::Event(Event::Focus(_))) {
                focused = false;
            }
            if let Some(read) = line.input(input, ctx) {
                if matches!(read, Read::Browse) {
                    self.kept = Some((line.draft.clone(), line.cursor));
                }
                break read;
            }
        };
        while let Ok(Some(input)) = session.next(Some(Duration::ZERO)) {
            if let Input::Key(key) = input {
                ahead.push_back(key);
            }
        }
        finish(session, surface);
        Some(read)
    }
}

/// The next key or event; `None` once termination was asked for or the
/// terminal went away.
fn next_input(session: &mut Session<()>) -> Option<Input<()>> {
    loop {
        if termination_requested() {
            return None;
        }
        match session.next(Some(TERMINATION_POLL)) {
            Ok(Some(input)) => return Some(input),
            Ok(None) => {}
            Err(_) => return None,
        }
    }
}

/// Remove the surface, leaving the scrollback as it was.
fn finish(session: &mut Session<()>, surface: Surface) {
    let _ = session.close_surface(surface, false);
}

/// One line being edited.
struct Line<'a> {
    /// The earlier lines, oldest first.
    history: &'a [String],
    draft: String,
    /// Byte offset in `draft`, on a character boundary.
    cursor: usize,
    /// Where Up and Down are in `history`, and the draft they left.
    browsing: Option<(usize, String)>,
    popup: Option<Popup>,
    palette: Option<Palette>,
    /// The drafts to go back to, newest last, with their carets.
    undo: Vec<(String, usize)>,
    /// Whether the last change typed a character into a word: the next one
    /// joins its undo step.
    typing: bool,
}

/// The completions for the word at the caret, refilled as it changes.
struct Popup {
    suggestions: Vec<Suggestion>,
    selected: usize,
    /// The text the suggestions replace, as typed: what the list marks.
    word: String,
}

impl Popup {
    /// The popup over `suggestions` for `draft`, keeping `keep` selected
    /// when it is still among them.
    fn new(suggestions: Vec<Suggestion>, draft: &str, keep: Option<&str>) -> Self {
        let word = suggestions
            .first()
            .and_then(|suggestion| {
                let end = suggestion.span.end.min(draft.len());
                draft.get(suggestion.span.start.min(end)..end)
            })
            .unwrap_or_default()
            .to_owned();
        let selected = keep
            .and_then(|value| suggestions.iter().position(|s| s.value == value))
            .unwrap_or(0);
        Self {
            suggestions,
            selected,
            word,
        }
    }

    fn step(&mut self, by: isize) {
        let count = self.suggestions.len() as isize;
        self.selected = (self.selected as isize + by).rem_euclid(count) as usize;
    }
}

impl<'a> Line<'a> {
    fn new(history: &'a [String]) -> Self {
        Self {
            history,
            draft: String::new(),
            cursor: 0,
            browsing: None,
            popup: None,
            palette: None,
            undo: Vec::new(),
            typing: false,
        }
    }

    /// Apply one key or event; the read is over when this returns one.
    fn input(&mut self, input: Input<()>, ctx: &mut Ctx) -> Option<Read> {
        if let Some(palette) = &mut self.palette {
            let outcome = match &input {
                Input::Key(key) => palette.key(key),
                Input::Event(event) => palette.event(event),
                Input::Msg(..) => Outcome::Continue,
            };
            match outcome {
                Outcome::Continue => {}
                Outcome::Close => self.palette = None,
                Outcome::Pick => {
                    let picked = palette.picked();
                    self.palette = None;
                    if let Some(line) = picked {
                        self.remember();
                        self.set(line);
                    }
                }
            }
            return None;
        }
        let before = (self.draft.clone(), self.cursor);
        let mut typed = false;
        let read = match input {
            Input::Key(key) => self.key(&key, ctx, &mut typed),
            Input::Event(Event::Edit(edit)) if edit.id == EDITOR => {
                self.edit(&edit);
                None
            }
            Input::Event(Event::Undo(undo)) if undo.id == EDITOR => {
                self.undo();
                return None;
            }
            // Tern submitting a prompt of its own, as if typed and entered.
            Input::Event(Event::Send(send)) if send.id == EDITOR => {
                return (!send.text.trim().is_empty())
                    .then(|| Read::Line(send.text.trim_end().to_owned()));
            }
            Input::Event(Event::Select(pick) | Event::Activate(pick)) => {
                self.click(&pick.item);
                None
            }
            Input::Event(_) | Input::Msg(..) => None,
        };
        self.changed(before, typed, ctx);
        read
    }

    /// After a key or an edit: an undo step for a changed draft, and the
    /// popup refilled for the word now at the caret, or closed when the
    /// caret left it.
    fn changed(&mut self, (draft, cursor): (String, usize), typed: bool, ctx: &mut Ctx) {
        if self.draft != draft {
            if !(typed && self.typing) {
                self.undo.push((draft, cursor));
                if self.undo.len() > UNDO_LIMIT {
                    self.undo.remove(0);
                }
            }
            self.typing = typed;
            if self.popup.is_some() {
                self.refill(ctx);
            }
        } else if self.cursor != cursor {
            self.typing = false;
            self.popup = None;
        }
    }

    /// Save the draft as an undo step before a change made outside a key.
    fn remember(&mut self) {
        self.undo.push((self.draft.clone(), self.cursor));
        self.typing = false;
    }

    fn undo(&mut self) {
        if let Some((draft, cursor)) = self.undo.pop() {
            self.draft = draft;
            self.cursor = cursor;
        }
        self.typing = false;
        self.popup = None;
    }

    fn key(&mut self, key: &Key, ctx: &mut Ctx, typed: &mut bool) -> Option<Read> {
        if let Some(popup) = &mut self.popup {
            if key.is("escape") {
                self.popup = None;
                return None;
            }
            if key.is("up") || key.is("shift+tab") || key.is("ctrl+p") {
                popup.step(-1);
                return None;
            }
            if key.is("down") || key.is("tab") || key.is("ctrl+n") {
                popup.step(1);
                return None;
            }
            if key.is("page_up") {
                popup.step(-(POPUP_ROWS as isize));
                return None;
            }
            if key.is("page_down") {
                popup.step(POPUP_ROWS as isize);
                return None;
            }
            if key.is("enter") {
                let suggestion = popup.suggestions[popup.selected].clone();
                self.apply(&suggestion);
                return None;
            }
        }
        if key.is("enter") {
            let line = self.draft.trim_end();
            return (!line.trim().is_empty()).then(|| Read::Line(line.to_owned()));
        }
        if key.is("ctrl+d") && self.draft.is_empty() {
            return Some(Read::Quit);
        }
        if key.is("ctrl+c") {
            if self.draft.is_empty() {
                return Some(Read::Interrupt);
            }
            self.set(String::new());
            return None;
        }
        if key.is("ctrl+l") {
            return Some(Read::Clear);
        }
        if key.is("ctrl+z") || key.is("ctrl+_") {
            self.undo();
        } else if key.is("tab") {
            self.complete(ctx);
        } else if key.is("f2") {
            return Some(Read::Browse);
        } else if key.is("alt+p") {
            self.open_palette(ctx.state, initial_tab(&self.draft));
        } else if key.is("ctrl+r") {
            self.open_palette(ctx.state, Tab::History);
        } else if key.is("up") || key.is("ctrl+p") {
            self.browse(-1);
        } else if key.is("down") || key.is("ctrl+n") {
            self.browse(1);
        } else if key.is("left") || key.is("ctrl+b") {
            self.cursor = self.boundary_before(self.cursor);
        } else if key.is("right") || key.is("ctrl+f") {
            if !self.take_ghost() {
                self.cursor = self.boundary_after(self.cursor);
            }
        } else if key.is("alt+left") || key.is("ctrl+left") || key.is("alt+b") {
            self.cursor = self.word_before(self.cursor);
        } else if key.is("alt+right") || key.is("ctrl+right") || key.is("alt+f") {
            self.cursor = self.word_after(self.cursor);
        } else if key.is("home") || key.is("ctrl+a") {
            self.cursor = 0;
        } else if key.is("end") || key.is("ctrl+e") {
            if !self.take_ghost() {
                self.cursor = self.draft.len();
            }
        } else if key.is("backspace") {
            let from = self.boundary_before(self.cursor);
            self.draft.replace_range(from..self.cursor, "");
            self.cursor = from;
        } else if key.is("delete") {
            let to = self.boundary_after(self.cursor);
            self.draft.replace_range(self.cursor..to, "");
        } else if key.is("ctrl+u") {
            self.draft.replace_range(..self.cursor, "");
            self.cursor = 0;
        } else if key.is("ctrl+k") {
            self.draft.truncate(self.cursor);
        } else if key.is("ctrl+w") || key.is("alt+backspace") || key.is("ctrl+backspace") {
            let from = self.word_before(self.cursor);
            self.draft.replace_range(from..self.cursor, "");
            self.cursor = from;
        } else if key.is("alt+d") || key.is("ctrl+delete") {
            let to = self.word_after(self.cursor);
            self.draft.replace_range(self.cursor..to, "");
        } else if key.name == "paste" {
            // Pasted lines become one line of commands, as WinDbg separates
            // them.
            let text = key.text.as_deref().unwrap_or_default();
            let lines: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect();
            self.insert(&lines.join("; "));
        } else if let Some(text) = key.typed() {
            let mut chars = text.chars();
            *typed = chars.next().is_some_and(|c| !c.is_whitespace()) && chars.next().is_none();
            self.insert(text);
        }
        None
    }

    fn set(&mut self, text: String) {
        self.cursor = text.len();
        self.draft = text;
        self.browsing = None;
        self.popup = None;
    }

    fn insert(&mut self, text: &str) {
        self.draft.insert_str(self.cursor, text);
        self.cursor += text.len();
    }

    /// Tern's native editing: replace UTF-16 `from..to` with `text` and put
    /// the caret at `cursor`. An edit computed against other text (keys in
    /// flight) is dropped.
    fn edit(&mut self, edit: &Edit) {
        if edit.len != self.draft.encode_utf16().count() {
            return;
        }
        let from = byte_offset(&self.draft, edit.from);
        let to = byte_offset(&self.draft, edit.to).max(from);
        self.draft.replace_range(from..to, &edit.text);
        self.cursor = byte_offset(&self.draft, edit.cursor);
    }

    fn boundary_before(&self, at: usize) -> usize {
        self.draft[..at]
            .char_indices()
            .next_back()
            .map_or(0, |(index, _)| index)
    }

    fn boundary_after(&self, at: usize) -> usize {
        self.draft[at..]
            .chars()
            .next()
            .map_or(at, |c| at + c.len_utf8())
    }

    /// The start of the word before `at`, skipping spaces first.
    fn word_before(&self, at: usize) -> usize {
        let head = self.draft[..at].trim_end();
        head.rfind(char::is_whitespace).map_or(0, |space| space + 1)
    }

    /// The end of the word after `at`, skipping spaces first.
    fn word_after(&self, at: usize) -> usize {
        let rest = &self.draft[at..];
        let start = rest.len() - rest.trim_start().len();
        let word = &rest[start..];
        at + start + word.find(char::is_whitespace).unwrap_or(word.len())
    }

    /// Up (`-1`) or Down (`1`) through the history, keeping the draft to
    /// come back to.
    fn browse(&mut self, by: isize) {
        let len = self.history.len();
        if len == 0 {
            return;
        }
        let (at, saved) = match self.browsing.take() {
            Some(browsing) => browsing,
            None if by < 0 => (len, self.draft.clone()),
            None => return,
        };
        let next = at as isize + by;
        if next >= len as isize {
            self.draft = saved;
        } else {
            let next = next.max(0) as usize;
            self.draft = self.history[next].clone();
            self.browsing = Some((next, saved));
        }
        self.cursor = self.draft.len();
    }

    /// What Right or End at the end of the line would add, drawn dim after
    /// the caret: the rest of the selected completion while the popup is
    /// open, else of the newest earlier line that starts with the draft.
    fn ghost(&self) -> String {
        if self.cursor != self.draft.len() {
            return String::new();
        }
        if let Some(popup) = &self.popup {
            return popup
                .suggestions
                .get(popup.selected)
                .filter(|_| !popup.word.is_empty())
                .and_then(|suggestion| suggestion.value.strip_prefix(popup.word.as_str()))
                .unwrap_or_default()
                .to_owned();
        }
        if self.draft.is_empty() {
            return String::new();
        }
        self.history
            .iter()
            .rev()
            .find(|line| line.len() > self.draft.len() && line.starts_with(&self.draft))
            .map(|line| line[self.draft.len()..].to_owned())
            .unwrap_or_default()
    }

    /// Take the ghost into the draft; whether there was one.
    fn take_ghost(&mut self) -> bool {
        let ghost = self.ghost();
        if ghost.is_empty() {
            return false;
        }
        self.insert(&ghost);
        true
    }

    fn suggestions(&self, ctx: &mut Ctx) -> Vec<Suggestion> {
        let (draft, cursor) = (self.draft.as_str(), self.cursor);
        let completer = &mut *ctx.completer;
        let mut suggestions = ctx
            .loan
            .lend(&ctx.state.ctx.target, || completer.complete(draft, cursor));
        suggestions.truncate(POPUP_LIMIT);
        suggestions
    }

    /// Tab: one completion is taken, several open the popup.
    fn complete(&mut self, ctx: &mut Ctx) {
        let suggestions = self.suggestions(ctx);
        match suggestions.len() {
            0 => {}
            1 => self.apply(&suggestions[0]),
            _ => self.popup = Some(Popup::new(suggestions, &self.draft, None)),
        }
    }

    /// Refill the open popup for the word at the caret: it follows typing
    /// and Backspace, and closes once the word ends, has nothing left to
    /// complete, or matches nothing.
    fn refill(&mut self, ctx: &mut Ctx) {
        let keep = self
            .popup
            .as_ref()
            .and_then(|popup| popup.suggestions.get(popup.selected))
            .map(|suggestion| suggestion.value.clone());
        let in_word = self.draft[..self.cursor]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_whitespace());
        self.popup = None;
        if !in_word {
            return;
        }
        let suggestions = self.suggestions(ctx);
        let popup = Popup::new(suggestions, &self.draft, keep.as_deref());
        let done = matches!(popup.suggestions.as_slice(), [only] if only.value == popup.word);
        if !popup.suggestions.is_empty() && !done {
            self.popup = Some(popup);
        }
    }

    fn apply(&mut self, suggestion: &Suggestion) {
        let end = suggestion.span.end.min(self.draft.len());
        let start = suggestion.span.start.min(end);
        self.draft.replace_range(start..end, &suggestion.value);
        self.cursor = start + suggestion.value.len();
        if suggestion.append_whitespace {
            self.insert(" ");
        }
        self.popup = None;
    }

    /// A click on a completion takes it.
    fn click(&mut self, item: &str) {
        let Some(popup) = &self.popup else {
            return;
        };
        let suggestion = item
            .rsplit('.')
            .next()
            .and_then(|key| key.strip_prefix('s'))
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| popup.suggestions.get(index))
            .cloned();
        if let Some(suggestion) = suggestion {
            self.apply(&suggestion);
        }
    }

    fn open_palette(&mut self, state: &ReplState, tab: Tab) {
        let mut seen = HashSet::new();
        let recent = self
            .history
            .iter()
            .rev()
            .filter(|line| seen.insert(line.trim()))
            .take(RECENT_LINES)
            .cloned()
            .collect();
        self.popup = None;
        self.palette = Some(Palette::new(
            state.palette_catalog(recent),
            &self.draft,
            tab,
        ));
    }

    fn view(&self, ctx: &Ctx) -> View {
        let state = ctx.state;
        let backend = state.ctx.backend.name();
        let thread = state.ctx.current_thread.as_str();
        let running = state.ctx.backend.is_running();
        let mut status = ui::status().child(ui::seg(backend).icon(Icon::Plug));
        if !thread.is_empty() {
            status = status.child(ui::seg([span("thread ", MUTED), span(thread, "info")]));
        }
        status = status.child(if running {
            ui::seg("running").icon(Icon::Play)
        } else {
            ui::seg("stopped").icon(Icon::Pause)
        });
        let hints: &[(&str, &str)] = if self.popup.is_some() {
            &[("↑↓", "choose"), ("Enter", "insert"), ("Esc", "close")]
        } else {
            &[
                ("Tab", "complete"),
                ("Alt+P", "palette"),
                ("F2", "browse"),
                ("Ctrl+R", "history"),
            ]
        };
        for (priority, (key, what)) in hints.iter().enumerate() {
            status = status.child(
                ui::seg([span(*key, ""), span(format!(" {what}"), MUTED)])
                    .side(Side::Right)
                    .priority((hints.len() - priority) as f64),
            );
        }
        let prompt = if thread.is_empty() {
            vec![span("ntoseye> ", MUTED)]
        } else {
            vec![
                span(format!("{backend}:"), MUTED),
                span(thread, "info"),
                span("> ", MUTED),
            ]
        };
        let input = ui::input()
            .key("ed")
            .text(self.draft.clone())
            .cursor(utf16(&self.draft, self.cursor))
            .prompt(prompt)
            .ghost(self.ghost())
            .placeholder("Enter a command".to_owned())
            .decor(decor(&self.draft, &ctx.completer.caches))
            .sendable(true);
        let mut view = View::new().dock(vec![Node::from(status), Node::from(input)]);
        if let Some(palette) = &self.palette {
            view = view.layer(vec![Node::from(palette.picker())]);
        } else if let Some(popup) = &self.popup {
            let mut list = ui::list()
                .key("list")
                .max_lines(POPUP_ROWS)
                .filter(popup.word.clone())
                .selected(format!("layer.popup.list.s{}", popup.selected));
            for (index, suggestion) in popup.suggestions.iter().enumerate() {
                let mut item = ui::item(suggestion.value.as_str()).key(format!("s{index}"));
                if let Some(description) = &suggestion.description {
                    // A kind sits at the row's end beside its icon; a
                    // command's summary follows the name.
                    item = match kind_icon(description) {
                        Some(icon) => item.icon(icon).value(description.as_str()),
                        None => item
                            .detail(description.split_whitespace().collect::<Vec<_>>().join(" ")),
                    };
                }
                list = list.child(item);
            }
            view = view.layer(vec![Node::from(
                ui::overlay()
                    .key("popup")
                    .anchor(Anchor::Caret(EDITOR.to_owned()))
                    .size(OverlaySize::Md)
                    .child(list),
            )]);
        }
        view
    }
}

/// The icon for what a completion is, from the completer's description.
fn kind_icon(description: &str) -> Option<Icon> {
    Some(match description {
        "Symbol" => Icon::Code,
        "Module" => Icon::Box,
        "Type" | "Structure" => Icon::Braces,
        "Field" => Icon::Hash,
        "Local" | "Variable" | "Result" | "Builtin" => Icon::Tag,
        "Register" => Icon::Binary,
        "vCPU" => Icon::Cpu,
        "Alias" => Icon::Link,
        _ if description.contains(" (PID ") => Icon::Activity,
        _ if description.contains(" @ 0x") => Icon::Pin,
        _ => return None,
    })
}

/// The field's decorations for `line`'s [`highlight`].
fn decor(line: &str, caches: &ReplCaches) -> Vec<Decor> {
    highlight(line, caches)
        .into_iter()
        .map(|(from, to, style)| Decor {
            from: utf16(line, from),
            to: utf16(line, to),
            s: style.to_owned(),
            fx: None,
        })
        .collect()
}

/// `line` colored as the field showed it, for the scrollback.
fn colored(line: &str, caches: &ReplCaches) -> String {
    let mut out = String::with_capacity(line.len() * 2);
    let mut at = 0;
    for (from, to, style) in highlight(line, caches) {
        out.push_str(&line[at..from]);
        let text = &line[from..to];
        let _ = match style {
            MNEMONIC => write!(out, "{}", text.bright_magenta()),
            SYMBOL => write!(out, "{}", text.bright_blue()),
            NUMBER | REGISTER => write!(out, "{}", text.cyan()),
            STRING => write!(out, "{}", text.green()),
            "error" => write!(out, "{}", text.red()),
            _ => write!(out, "{}", text.bright_black()),
        };
        at = to;
    }
    out.push_str(&line[at..]);
    out
}

/// The line's colors, as byte ranges and span tokens: a command name as a
/// keyword when it names one, red when nothing starts with it; switches and
/// separators quiet; numbers, `@registers`, `module!symbol` and strings as
/// the views color them.
fn highlight(line: &str, caches: &ReplCaches) -> Vec<(usize, usize, &'static str)> {
    let mut ranges = Vec::new();
    let mut mark = |from: usize, to: usize, style: &'static str| {
        if from < to {
            ranges.push((from, to, style));
        }
    };
    let segments = split_command_list(line).unwrap_or_else(|_| vec![line.trim()]);
    let mut previous_end = 0;
    for segment in segments {
        let start = segment.as_ptr() as usize - line.as_ptr() as usize;
        for (at, _) in line[previous_end..start].match_indices(';') {
            mark(previous_end + at, previous_end + at + 1, MUTED);
        }
        previous_end = start + segment.len();
        if is_comment(segment) {
            mark(start, previous_end, DIM);
            continue;
        }
        if segment.starts_with('~') {
            let end = segment.find(char::is_whitespace).unwrap_or(segment.len());
            mark(start, start + end, MNEMONIC);
            arguments(&segment[end..], start + end, &mut mark);
            continue;
        }
        if let Some((token, _)) = script_file_token(segment) {
            mark(start, start + token.len(), MNEMONIC);
            continue;
        }
        let Ok(Some(parsed)) = parse_command(segment) else {
            continue;
        };
        let name_start = parsed.name.as_ptr() as usize - line.as_ptr() as usize;
        let name_end = name_start + parsed.name.len();
        match command_name(parsed.name, caches) {
            Name::Known => mark(name_start, name_end, MNEMONIC),
            Name::Partial => {}
            Name::Unknown => mark(name_start, name_end, "error"),
        }
        let tail_start = name_end;
        arguments(&line[tail_start..previous_end], tail_start, &mut mark);
    }
    ranges
}

/// Whether a command name is one, could become one as it is typed, or
/// can't.
enum Name {
    Known,
    Partial,
    Unknown,
}

fn command_name(name: &str, caches: &ReplCaches) -> Name {
    let registry = command_registry();
    let aliases = caches.aliases.read().unwrap();
    let users = caches.user_commands.read().unwrap();
    let mut others = aliases
        .iter()
        .map(|(alias, _)| alias.as_str())
        .chain(users.iter().map(|(user, ..)| user.as_str()));
    if registry.get(name).is_some() || others.clone().any(|other| other == name) {
        Name::Known
    } else if registry.has_prefix(name) || others.any(|other| other.starts_with(name)) {
        Name::Partial
    } else {
        Name::Unknown
    }
}

/// Color the arguments in `tail`, which starts at byte `offset` of the line.
fn arguments(tail: &str, offset: usize, mark: &mut impl FnMut(usize, usize, &'static str)) {
    let mut chars = tail.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let mut end = start + c.len_utf8();
        if c == '"' {
            for (at, next) in chars.by_ref() {
                end = at + next.len_utf8();
                if next == '"' {
                    break;
                }
            }
            mark(offset + start, offset + end, STRING);
            continue;
        }
        while let Some(&(at, next)) = chars.peek() {
            if next.is_whitespace() {
                break;
            }
            end = at + next.len_utf8();
            chars.next();
        }
        for (from, to, style) in argument(&tail[start..end]) {
            mark(offset + start + from, offset + start + to, style);
        }
    }
}

/// The colored ranges of one argument, in bytes from its start.
fn argument(token: &str) -> Vec<(usize, usize, &'static str)> {
    let rest = &token[1..];
    let word = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    };
    if (token.starts_with('/') || token.starts_with('-'))
        && rest.chars().all(|c| c.is_ascii_alphabetic())
        && !rest.is_empty()
    {
        return vec![(0, token.len(), MUTED)];
    }
    if token.starts_with('@') && word(rest) {
        return vec![(0, token.len(), REGISTER)];
    }
    if is_number(token) {
        return vec![(0, token.len(), NUMBER)];
    }
    if let Some(bang) = token.find('!')
        && bang > 0
        && word(&token[..bang])
    {
        let name_end = token[bang..]
            .find("+0x")
            .map_or(token.len(), |plus| bang + plus);
        return vec![
            (0, bang + 1, MUTED),
            (bang + 1, name_end, SYMBOL),
            (name_end, token.len(), MUTED),
        ];
    }
    Vec::new()
}

/// A number as WinDbg reads one: `0x`, `0n` or `0y` prefixed, all decimal
/// digits, or an address of 8 or more hex digits (a backtick may split it).
fn is_number(token: &str) -> bool {
    let digits = |text: &str, radix: u32| {
        !text.is_empty() && text.chars().all(|c| c == '`' || c.is_digit(radix))
    };
    let lower = token.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        return digits(hex, 16);
    }
    if let Some(decimal) = lower.strip_prefix("0n") {
        return digits(decimal, 10);
    }
    if let Some(binary) = lower.strip_prefix("0y") {
        return digits(binary, 2);
    }
    digits(token, 10) || (token.len() >= 8 && digits(token, 16))
}

/// The UTF-16 offset of byte `at` in `text`.
fn utf16(text: &str, at: usize) -> usize {
    text[..at].encode_utf16().count()
}

/// The byte offset in `text` of UTF-16 offset `units`, clamped to the end
/// and rounded down to a character boundary.
fn byte_offset(text: &str, units: usize) -> usize {
    let mut seen = 0;
    for (index, c) in text.char_indices() {
        if seen >= units {
            return index;
        }
        seen += c.len_utf16();
        if seen > units {
            return index;
        }
    }
    text.len()
}

/// Write `bytes` to the terminal at once.
fn write_now(bytes: &[u8]) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(bytes);
    let _ = stdout.flush();
}
