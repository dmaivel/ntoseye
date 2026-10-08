//! The completion popup a Tern input field shows at its caret: the Tern
//! prompt's and the browser's go-to and find fields share it.

use reedline::Suggestion;
use tern_sdk::Node;
use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Anchor, Icon, OverlaySize};

use crate::repl::line_editor::SEARCH_LIMIT;

/// How many completions the popup lists.
pub const POPUP_LIMIT: usize = 100;
/// How many rows the popup shows before it scrolls.
pub const POPUP_ROWS: u32 = 10;

/// The completions for the word at the caret, refilled as it changes.
pub struct Popup {
    pub suggestions: Vec<Suggestion>,
    pub selected: usize,
    /// The text the suggestions replace, as typed: what the list marks.
    pub word: String,
    /// How many completions past [`POPUP_LIMIT`] the list leaves out.
    pub more: usize,
    /// Whether the completer stopped looking before the end, so `more`
    /// counts only what it found.
    pub capped: bool,
}

/// What a key did to an open popup.
pub enum PopupKey {
    /// It moved the selection.
    Moved,
    /// Escape: close the popup, keeping the text.
    Close,
    /// Enter: put this suggestion in the text.
    Take(Suggestion),
    /// Enter on the row that counts the completions left out: search them
    /// all (the prompt's Alt+P).
    More,
    /// Not the popup's key.
    Ignored,
}

impl Popup {
    /// The popup over the first [`POPUP_LIMIT`] of `suggestions` for
    /// `draft`, keeping `keep` selected when it is still among them.
    pub fn new(mut suggestions: Vec<Suggestion>, draft: &str, keep: Option<&str>) -> Self {
        let total = suggestions.len();
        suggestions.truncate(POPUP_LIMIT);
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
            more: total - total.min(POPUP_LIMIT),
            capped: total >= SEARCH_LIMIT,
        }
    }

    /// The popup for `draft` worth showing as it is typed: not when nothing
    /// matches, the one match is what was typed, or nothing is typed of the
    /// word, such as after `(`, where every symbol would match and Enter
    /// would take the first; nor for a number (a word that starts with a
    /// digit, as no symbol does), which fuzzy-matches symbols such as
    /// `…,0,1>` that Enter would take for it.
    pub fn open(suggestions: Vec<Suggestion>, draft: &str, keep: Option<&str>) -> Option<Self> {
        let popup = Self::new(suggestions, draft, keep);
        let done = matches!(popup.suggestions.as_slice(), [only] if only.value == popup.word);
        let number = popup.word.starts_with(|c: char| c.is_ascii_digit());
        (!popup.suggestions.is_empty() && !done && !popup.word.is_empty() && !number)
            .then_some(popup)
    }

    fn step(&mut self, by: isize) {
        // The row counting what is left out is one more stop.
        let count = (self.suggestions.len() + usize::from(self.more > 0)) as isize;
        self.selected = (self.selected as isize + by).rem_euclid(count) as usize;
    }

    /// Whether the row that counts what is left out is selected.
    fn on_more(&self) -> bool {
        self.selected == self.suggestions.len()
    }

    /// The selected suggestion's value, to keep it selected across a refill.
    pub fn selected_value(&self) -> Option<&str> {
        self.suggestions
            .get(self.selected)
            .map(|suggestion| suggestion.value.as_str())
    }

    pub fn key(&mut self, key: &Key) -> PopupKey {
        if key.is("escape") {
            return PopupKey::Close;
        }
        if key.is("up") || key.is("shift+tab") || key.is("ctrl+p") {
            self.step(-1);
        } else if key.is("down") || key.is("tab") || key.is("ctrl+n") {
            self.step(1);
        } else if key.is("page_up") {
            self.step(-(POPUP_ROWS as isize));
        } else if key.is("page_down") {
            self.step(POPUP_ROWS as isize);
        } else if key.is("enter") {
            if self.on_more() {
                return PopupKey::More;
            }
            return PopupKey::Take(self.suggestions[self.selected].clone());
        } else {
            return PopupKey::Ignored;
        }
        PopupKey::Moved
    }

    /// The rest of the selected suggestion after what was typed, drawn dim
    /// after the caret.
    pub fn ghost(&self) -> &str {
        self.suggestions
            .get(self.selected)
            .filter(|_| !self.word.is_empty())
            .and_then(|suggestion| suggestion.value.strip_prefix(self.word.as_str()))
            .unwrap_or_default()
    }

    /// The suggestion a click on list item `item` names.
    pub fn clicked(&self, item: &str) -> Option<&Suggestion> {
        item.rsplit('.')
            .next()
            .and_then(|key| key.strip_prefix('s'))
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| self.suggestions.get(index))
    }

    /// The list in an overlay at the caret of field `field`, for the
    /// `layer` region: its items are `layer.popup.list.s<n>`. When the list
    /// leaves completions out, a last row says how many, and that typing
    /// narrows them, or `palette` (the prompt's Alt+P) lists them all.
    pub fn overlay<M>(&self, field: &str, palette: bool) -> Node<M> {
        let mut list = ui::list()
            .key("list")
            .max_lines(POPUP_ROWS)
            .filter(self.word.clone())
            .selected(if self.on_more() {
                "layer.popup.list.more".to_owned()
            } else {
                format!("layer.popup.list.s{}", self.selected)
            });
        for (index, suggestion) in self.suggestions.iter().enumerate() {
            let mut item = ui::item(suggestion.value.as_str()).key(format!("s{index}"));
            if let Some(description) = &suggestion.description {
                // A kind sits at the row's end beside its icon; a
                // command's summary follows the name.
                item = match kind_icon(description) {
                    Some(icon) => item.icon(icon).value(description.as_str()),
                    None => {
                        item.detail(description.split_whitespace().collect::<Vec<_>>().join(" "))
                    }
                };
            }
            list = list.child(item);
        }
        if self.more > 0 {
            let plus = if self.capped { "+" } else { "" };
            let mut item = ui::item(format!("{}{plus} more", self.more)).key("more");
            item = if palette {
                item.detail("keep typing, or")
                    .hint(vec!["Alt".to_owned(), "P".to_owned()])
            } else {
                item.detail("keep typing")
            };
            list = list.child(item);
        }
        ui::overlay()
            .key("popup")
            .anchor(Anchor::Caret(field.to_owned()))
            .size(OverlaySize::Md)
            .child(list)
            .into()
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

#[cfg(test)]
mod tests {
    use reedline::Span;

    use super::*;

    fn completions(count: usize, at: usize) -> Vec<Suggestion> {
        (0..count)
            .map(|index| Suggestion {
                value: format!("nt!S{index}"),
                span: Span::new(at, at),
                ..Suggestion::default()
            })
            .collect()
    }

    /// Typing past a name leaves no word to complete: every symbol would
    /// match, and Enter would take the first, so nothing opens as you type;
    /// Tab still lists them, and the list says what it leaves out.
    #[test]
    fn opens_on_a_word_and_counts_what_it_leaves_out() {
        let draft = "poi(nt!PsInitialSystemProcess)";
        let after = completions(150, draft.len());
        assert!(Popup::open(after.clone(), draft, None).is_none());

        let tab = Popup::new(after, draft, None);
        assert_eq!(tab.suggestions.len(), POPUP_LIMIT);
        assert_eq!((tab.more, tab.capped), (50, false));

        // Past the completer's own limit, the count is only what it found.
        let capped = Popup::new(completions(SEARCH_LIMIT, 0), "", None);
        assert_eq!(
            (capped.more, capped.capped),
            (SEARCH_LIMIT - POPUP_LIMIT, true)
        );

        let mut word = completions(3, 0);
        for suggestion in &mut word {
            suggestion.span = Span::new(0, 2);
        }
        let typed = Popup::open(word, "nt", None).expect("a word opens the popup");
        assert_eq!((typed.word.as_str(), typed.more), ("nt", 0));

        // A number is not completed as it is typed; Tab still lists.
        let mut number = completions(3, 0);
        for suggestion in &mut number {
            suggestion.span = Span::new(0, 4);
        }
        assert!(Popup::open(number.clone(), "0x10", None).is_none());
        assert_eq!(Popup::new(number, "0x10", None).suggestions.len(), 3);
    }

    /// Down from the last completion shown lands on the row that counts
    /// the rest, where Enter searches them all; past it, the list wraps.
    #[test]
    fn the_row_counting_the_rest_is_a_stop() {
        let key = |name: &str| Key {
            name: name.to_owned(),
            ..Key::default()
        };
        let mut popup = Popup::new(completions(POPUP_LIMIT + 5, 0), "", None);
        assert!(matches!(popup.key(&key("up")), PopupKey::Moved));
        assert!(matches!(popup.key(&key("enter")), PopupKey::More));
        assert_eq!(popup.ghost(), "");
        assert!(matches!(popup.key(&key("down")), PopupKey::Moved));
        assert!(matches!(popup.key(&key("enter")), PopupKey::Take(s) if s.value == "nt!S0"));

        let mut whole = Popup::new(completions(3, 0), "", None);
        whole.key(&key("up"));
        assert!(matches!(whole.key(&key("enter")), PopupKey::Take(s) if s.value == "nt!S2"));
    }
}
