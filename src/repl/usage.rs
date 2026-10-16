//! A command's usage line and completion, generated from its arguments.
//!
//! `#[command]` describes each argument the line gives as an [`ArgGrammar`]:
//! a typed argument by its name and type, a custom parser by the
//! [`Grammar`] it declares with `#[grammar(...)]`. The functions here join
//! those at compile time into the [`CommandSpec`](super::CommandSpec)'s
//! `usage` text and [`CompletionSpec`](super::CompletionSpec), so neither
//! can drift from what the parser accepts.
//!
//! The notation (WinDbg's and POSIX's):
//!
//! - `<name>` is a required word and `[name]` an optional one; `...` after
//!   one repeats it: `<name>...` is one or more, `[name]...` any number;
//! - a switch or option is written as typed, `[/p]`, `[-v]`, with its value
//!   after it, `[/p <processor>]`;
//! - `a|b` (no spaces) are alternatives inside one argument, `[+|-]value`;
//! - nested brackets are an optional group, `[bus [device]]`. Optional words
//!   in a row nest, since the line gives them in turn: two arguments whose
//!   fragments are `[{}]` (an optional word: a typed `Option`, or a parser
//!   declaring one) read `[address [flags]]`;
//! - ` | ` (spaced) separates whole forms of the line. The usage text shows
//!   each form on its own line, starting with the command name.
//!
//! Names are kebab-case: the parameter's name, or `#[arg(name = "...")]`.

use crate::repl::CompletionStrategy;

/// The grammar of one argument: its usage fragment and how its words
/// complete. A custom parser declares one with `#[grammar(...)]`.
#[derive(Clone, Copy, Debug)]
pub struct Grammar {
    /// The fragment in the notation above; `{}` stands for the argument's
    /// name. Empty for an argument the line has no word for.
    pub usage: &'static str,
    /// The completion of each word, in order.
    pub words: &'static [CompletionStrategy],
    /// The completion of every word after `words`, for an argument that
    /// takes the rest of the line; `None` when it takes no more.
    pub rest: Option<CompletionStrategy>,
}

/// One argument of a command line: its name and its grammar.
#[derive(Clone, Copy, Debug)]
pub struct ArgGrammar {
    pub name: &'static str,
    pub grammar: Grammar,
}

/// A `#[grammar(operation)]` parser hands its words to the operation,
/// which reads them itself, so each argument it parses describes them
/// (`#[arg(parse = f, usage = "...")]`): the parser's grammar is `None`.
pub const fn declared(grammar: Option<Grammar>) -> Grammar {
    match grammar {
        Some(grammar) => grammar,
        None => panic!(
            "this parser hands its words to the operation: describe them with \
             #[arg(usage = \"...\")]"
        ),
    }
}

/// Assert that an argument's own `usage` describes the words of a
/// `#[grammar(operation)]` parser, not one that declares its grammar.
pub const fn described(parser: Option<Grammar>, argument: Grammar) -> Grammar {
    assert!(
        parser.is_none(),
        "this parser declares its usage with #[grammar]: drop the argument's `usage`"
    );
    argument
}

/// The length of the usage text of command `name` with `args`.
pub const fn usage_len(name: &str, args: &[ArgGrammar]) -> usize {
    render(name, args, &mut [])
}

/// The usage text of command `name` with `args`, as bytes: `N` is
/// [`usage_len`].
pub const fn usage_bytes<const N: usize>(name: &str, args: &[ArgGrammar]) -> [u8; N] {
    let mut out = [0; N];
    render(name, args, &mut out);
    out
}

/// `bytes` (from [`usage_bytes`]) as text.
pub const fn usage_text(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => panic!("a usage fragment is not UTF-8"),
    }
}

/// How many completion entries [`completion_words`] gives.
pub const fn completion_len(args: &[ArgGrammar]) -> usize {
    let mut len = 0;
    let mut index = 0;
    while index < args.len() {
        let grammar = args[index].grammar;
        len += grammar.words.len();
        if grammar.rest.is_some() {
            break;
        }
        index += 1;
    }
    len
}

/// The completion of each word, in order: every argument's, up to the first
/// one that takes the rest of the line (the words after it have no fixed
/// position). `N` is [`completion_len`].
pub const fn completion_words<const N: usize>(args: &[ArgGrammar]) -> [CompletionStrategy; N] {
    let mut out = [CompletionStrategy::None; N];
    let mut at = 0;
    let mut index = 0;
    while index < args.len() {
        let grammar = args[index].grammar;
        let mut word = 0;
        while word < grammar.words.len() {
            out[at] = grammar.words[word];
            at += 1;
            word += 1;
        }
        if grammar.rest.is_some() {
            break;
        }
        index += 1;
    }
    out
}

/// The completion of the words after [`completion_words`]: the rest of the
/// line's, or none.
pub const fn completion_rest(args: &[ArgGrammar]) -> CompletionStrategy {
    let mut index = 0;
    while index < args.len() {
        if let Some(rest) = args[index].grammar.rest {
            return rest;
        }
        index += 1;
    }
    CompletionStrategy::None
}

const FORM_SEPARATOR: &[u8] = b" | ";

/// The fragment of an optional positional word, which nests with the next.
const OPTIONAL_WORD: &[u8] = b"[{}]";

/// Write the usage text into `out` (nothing when it is empty) and return
/// its length: a line per form, each the command name and the arguments'
/// fragments, optional words in a row nested. One argument at most may have
/// several forms.
const fn render(name: &str, args: &[ArgGrammar], out: &mut [u8]) -> usize {
    let mut forms_of = None;
    let mut index = 0;
    while index < args.len() {
        if form_count(args[index].grammar.usage.as_bytes()) > 1 {
            assert!(
                forms_of.is_none(),
                "only one argument of a command may have several forms (` | `)"
            );
            forms_of = Some(index);
        }
        index += 1;
    }
    let forms = match forms_of {
        Some(index) => form_count(args[index].grammar.usage.as_bytes()),
        None => 1,
    };
    let mut at = 0;
    let mut form = 0;
    while form < forms {
        if form > 0 {
            at = put(out, at, b"\n");
        }
        at = put(out, at, name.as_bytes());
        // Optional words opened and not yet closed (`[a [b`).
        let mut open = 0;
        let mut index = 0;
        while index < args.len() {
            let fragment = fragment_of(args, index, forms_of, form);
            let arg_name = args[index].name.as_bytes();
            if is_optional_word(fragment) {
                at = put(out, at, b" [");
                at = put(out, at, arg_name);
                open += 1;
                if !is_optional_word(next_fragment(args, index, forms_of, form)) {
                    while open > 0 {
                        at = put(out, at, b"]");
                        open -= 1;
                    }
                }
            } else if !fragment.is_empty() {
                at = put(out, at, b" ");
                at = put_fragment(out, at, fragment, arg_name);
            }
            index += 1;
        }
        form += 1;
    }
    at
}

/// Argument `index`'s fragment in form `form` of the line.
const fn fragment_of(
    args: &[ArgGrammar],
    index: usize,
    forms_of: Option<usize>,
    form: usize,
) -> &'static [u8] {
    let fragment = args[index].grammar.usage.as_bytes();
    match forms_of {
        Some(forms_of) if forms_of == index => nth_form(fragment, form),
        _ => fragment,
    }
}

/// The next fragment after argument `index` that shows a word, or none.
const fn next_fragment(
    args: &[ArgGrammar],
    mut index: usize,
    forms_of: Option<usize>,
    form: usize,
) -> &'static [u8] {
    index += 1;
    while index < args.len() {
        let fragment = fragment_of(args, index, forms_of, form);
        if !fragment.is_empty() {
            return fragment;
        }
        index += 1;
    }
    &[]
}

const fn is_optional_word(fragment: &[u8]) -> bool {
    fragment.len() == OPTIONAL_WORD.len() && starts_with(fragment, 0, OPTIONAL_WORD)
}

/// How many forms ` | ` separates in `fragment`.
const fn form_count(fragment: &[u8]) -> usize {
    let mut count = 1;
    let mut at = 0;
    while at < fragment.len() {
        if starts_with(fragment, at, FORM_SEPARATOR) {
            count += 1;
            at += FORM_SEPARATOR.len();
        } else {
            at += 1;
        }
    }
    count
}

/// The `n`th form of `fragment`.
const fn nth_form(fragment: &[u8], n: usize) -> &[u8] {
    let mut form = 0;
    let mut start = 0;
    let mut at = 0;
    while at <= fragment.len() {
        let end = at == fragment.len();
        if end || starts_with(fragment, at, FORM_SEPARATOR) {
            if form == n {
                return fragment.split_at(at).0.split_at(start).1;
            }
            form += 1;
            at += FORM_SEPARATOR.len();
            start = at;
        } else {
            at += 1;
        }
    }
    panic!("no such form")
}

/// Write `fragment` with each `{}` replaced by `name`.
const fn put_fragment(out: &mut [u8], mut at: usize, fragment: &[u8], name: &[u8]) -> usize {
    let mut index = 0;
    while index < fragment.len() {
        if starts_with(fragment, index, b"{}") {
            at = put(out, at, name);
            index += 2;
        } else {
            at = put(out, at, fragment.split_at(index).1.split_at(1).0);
            index += 1;
        }
    }
    at
}

const fn starts_with(text: &[u8], at: usize, prefix: &[u8]) -> bool {
    if at + prefix.len() > text.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if text[at + index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Write `bytes` at `at` (unless `out` is empty: counting) and return the
/// position after them.
const fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    if !out.is_empty() {
        let mut index = 0;
        while index < bytes.len() {
            out[at + index] = bytes[index];
            index += 1;
        }
    }
    at + bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn arg(name: &'static str, usage: &'static str) -> ArgGrammar {
        ArgGrammar {
            name,
            grammar: Grammar {
                usage,
                words: &[],
                rest: None,
            },
        }
    }

    fn usage(name: &str, args: &[ArgGrammar]) -> String {
        let mut out = vec![0; usage_len(name, args)];
        render(name, args, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn renders_fragments_and_forms() {
        assert_eq!(usage("bl", &[]), "bl");
        assert_eq!(
            usage("!job", &[arg("address", "[{}]"), arg("flags", "[{}]")]),
            "!job [address [flags]]"
        );
        assert_eq!(
            usage(
                "!sprocess",
                &[
                    arg("session", "[{}]"),
                    arg("memory", ""),
                    arg("flags", "[{}]"),
                    arg("x", "[-v]")
                ]
            ),
            "!sprocess [session [flags]] [-v]"
        );
        assert_eq!(
            usage(
                "db",
                &[arg("memory", ""), arg("range", "<address> [L<count>]")]
            ),
            "db <address> [L<count>]"
        );
        assert_eq!(
            usage(
                "!alpc",
                &[arg("query", "/p <port> | /m <message>"), arg("x", "[-v]")]
            ),
            "!alpc /p <port> [-v]\n!alpc /m <message> [-v]"
        );
    }
}
