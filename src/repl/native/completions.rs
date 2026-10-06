//! The completion popup a Tern input field shows at its caret: the Tern
//! prompt's and the browser's go-to and find fields share it.

use reedline::Suggestion;
use tern_sdk::Node;
use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Anchor, Icon, OverlaySize};

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
}

/// What a key did to an open popup.
pub enum PopupKey {
    /// It moved the selection.
    Moved,
    /// Escape: close the popup, keeping the text.
    Close,
    /// Enter: put this suggestion in the text.
    Take(Suggestion),
    /// Not the popup's key.
    Ignored,
}

impl Popup {
    /// The popup over `suggestions` for `draft`, keeping `keep` selected
    /// when it is still among them.
    pub fn new(suggestions: Vec<Suggestion>, draft: &str, keep: Option<&str>) -> Self {
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

    /// The popup for `draft` worth showing: not when nothing matches or
    /// the one match is what was typed.
    pub fn open(suggestions: Vec<Suggestion>, draft: &str, keep: Option<&str>) -> Option<Self> {
        let popup = Self::new(suggestions, draft, keep);
        let done = matches!(popup.suggestions.as_slice(), [only] if only.value == popup.word);
        (!popup.suggestions.is_empty() && !done).then_some(popup)
    }

    fn step(&mut self, by: isize) {
        let count = self.suggestions.len() as isize;
        self.selected = (self.selected as isize + by).rem_euclid(count) as usize;
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
    /// `layer` region: its items are `layer.popup.list.s<n>`.
    pub fn overlay<M>(&self, field: &str) -> Node<M> {
        let mut list = ui::list()
            .key("list")
            .max_lines(POPUP_ROWS)
            .filter(self.word.clone())
            .selected(format!("layer.popup.list.s{}", self.selected));
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
