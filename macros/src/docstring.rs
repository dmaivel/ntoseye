//! Python docstrings from doc comments. Rustdoc's intra-doc links mean
//! nothing to a Python reader and name the Rust module a type lives in, so
//! a docstring has their text instead:
//!
//! - `` [`a::b::Name`] `` becomes `` `Name` ``, and `` [`Self::x`] ``
//!   becomes `` `x` ``;
//! - `[text](target)` and `[text][label]` become `text`, unless the target
//!   is a URL (`https://...`), which stays a markdown link.

use syn::{Attribute, Expr, ExprLit, Lit, LitStr, Meta};

/// `attr` as a docstring line: a `#[doc = "..."]` with its intra-doc links
/// as plain text. Other attributes are returned as they are.
pub fn python_doc(attr: &Attribute) -> Attribute {
    if let Meta::NameValue(value) = &attr.meta
        && let Expr::Lit(ExprLit {
            lit: Lit::Str(text),
            ..
        }) = &value.value
    {
        let line = text.value();
        let plain = plain_links(&line);
        if plain != line {
            let plain = LitStr::new(&plain, text.span());
            return syn::parse_quote!(#[doc = #plain]);
        }
    }
    attr.clone()
}

/// `line` with each intra-doc link as plain text. A `[` after a backslash
/// is not a link.
pub fn plain_links(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find('[') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match link(after).filter(|_| !rest[..open].ends_with('\\')) {
            Some((text, len)) => {
                out.push_str(&text);
                rest = &after[len..];
            }
            None => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text of the intra-doc link whose `[` comes just before `after`, and
/// the length of the rest of the link in `after`; `None` when no
/// intra-doc link starts there (a URL link, or brackets in prose).
fn link(after: &str) -> Option<(String, usize)> {
    let close = after.find(']')?;
    let text = &after[..close];
    let tail = &after[close + 1..];
    if let Some(target) = tail.strip_prefix('(') {
        let end = target.find(')')?;
        return (!is_url(&target[..end])).then(|| (text.to_string(), close + 2 + end + 1));
    }
    if let Some(label) = tail.strip_prefix('[') {
        let end = label.find(']')?;
        return Some((text.to_string(), close + 2 + end + 1));
    }
    let code = text.strip_prefix('`')?.strip_suffix('`')?;
    let name = item_name(code)?;
    Some((format!("`{name}`"), close + 1))
}

fn is_url(target: &str) -> bool {
    target.contains("://") || target.starts_with("mailto:")
}

/// The last segment of the Rust path `code` names, with its `()` or `!`
/// suffix but without a disambiguator (`struct@`); `None` when `code` is
/// not a path.
fn item_name(code: &str) -> Option<&str> {
    let path = code.split_once('@').map_or(code, |(_, path)| path);
    let bare = path
        .strip_suffix("()")
        .or_else(|| path.strip_suffix('!'))
        .unwrap_or(path);
    let is_ident = |segment: &str| {
        segment
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
            && segment.chars().all(|c| c.is_alphanumeric() || c == '_')
    };
    if !bare.split("::").all(is_ident) {
        return None;
    }
    path.rsplit("::").next()
}

#[cfg(test)]
mod tests {
    use super::plain_links;

    #[test]
    fn intra_doc_links_become_their_text() {
        assert_eq!(
            plain_links("in [`crate::nt::target::VP_STATE_REGISTERS`] order"),
            "in `VP_STATE_REGISTERS` order"
        );
        assert_eq!(plain_links("see [`Self::granule`]."), "see `granule`.");
        assert_eq!(plain_links("[`fn@a::run()`], [`m!`]"), "`run()`, `m!`");
        assert_eq!(plain_links("a [`Stop`](crate::session::Stop)"), "a `Stop`");
        assert_eq!(plain_links("the [stop](Stop) and [x][y]"), "the stop and x");
    }

    #[test]
    fn other_brackets_stay() {
        for line in [
            "[docs](https://example.com/a)",
            "`!job [address [flags]]`",
            "dq [rsp], [`a b`], [`0x10`], \\[`Name`]",
            "an unclosed [`Name",
        ] {
            assert_eq!(plain_links(line), line);
        }
    }
}
