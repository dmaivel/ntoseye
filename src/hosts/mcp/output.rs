//! Long `command` results, cut into pages that fit an agent's context and
//! kept whole in memory for the `output` tool. Nothing is run again to see
//! the rest, and nothing is written where a client may not reach it.

use std::collections::VecDeque;

/// The most text one result carries: about 12k tokens of debugger output,
/// whose hex runs near two characters a token.
pub const PAGE_CHARS: usize = 24_000;
/// How much paged output is kept for `output`, the oldest dropped first.
const KEPT_BYTES: usize = 64 << 20;

/// Kept outputs, oldest first.
#[derive(Default)]
pub struct OutputStore {
    next_id: u64,
    kept: VecDeque<Kept>,
    bytes: usize,
}

struct Kept {
    id: u64,
    lines: Vec<Line>,
    bytes: usize,
}

/// One kept line, or a page-sized piece of a line longer than a page, so
/// that every part of it can be read at an offset of its own.
struct Line {
    text: String,
    /// The line goes on in the piece at the next offset.
    continues: bool,
}

/// The lines of one page and the offset after the last of them.
struct Page {
    text: String,
    end: usize,
}

impl OutputStore {
    /// `text` as one result: whole, without the spaces that pad table rows
    /// at their ends, when it fits; else its first page, kept whole, with a
    /// footer that says how to read the rest.
    pub fn fit(&mut self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
        let chars: usize = lines.iter().map(|line| line.len() + 1).sum();
        if chars <= PAGE_CHARS {
            return joined(&lines);
        }
        let lines = pieces(&lines);
        let page = page(&lines, 0, None);
        let total = lines.len();
        let id = self.keep(lines);
        format!(
            "{}[output {id}: {total} lines, offsets 0-{} shown; the output tool reads on from \
             offset {}, or with a filter finds lines in it]\n",
            page.text,
            page.end - 1,
            page.end
        )
    }

    /// The lines of output `id` from `offset`, at most `limit` of them and a
    /// page's worth; with `filter`, only the lines that contain it, ignoring
    /// case, each after its offset.
    pub fn read(
        &self,
        id: u64,
        offset: usize,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<String, String> {
        let kept = self
            .kept
            .iter()
            .find(|kept| kept.id == id)
            .ok_or_else(|| self.missing(id))?;
        let total = kept.lines.len();
        if limit == Some(0) {
            return Err("a limit of 0 reads no lines; give at least 1".to_string());
        }
        if offset >= total {
            return Err(format!(
                "output {id} has {total} lines, so offset {offset} is past its end"
            ));
        }
        let Some(filter) = filter.filter(|filter| !filter.is_empty()) else {
            let page = page(&kept.lines, offset, limit);
            let rest = if page.end < total {
                format!("next offset {}", page.end)
            } else {
                "the end".to_string()
            };
            return Ok(format!(
                "{}[output {id}: offsets {offset}-{} of {total} lines; {rest}]\n",
                page.text,
                page.end - 1
            ));
        };
        let needle = filter.to_lowercase();
        let mut text = String::new();
        let mut found = 0;
        let mut scanned = offset;
        for (at, line) in kept.lines.iter().enumerate().skip(offset) {
            if limit.is_some_and(|limit| found == limit) {
                break;
            }
            if line.text.to_lowercase().contains(&needle) {
                let numbered = format!("{at}: {}", line.text);
                if !text.is_empty() && text.len() + numbered.len() + 1 > PAGE_CHARS {
                    break;
                }
                text.push_str(&numbered);
                push_end(&mut text, line, at);
                found += 1;
            }
            scanned = at + 1;
        }
        let rest = if scanned < total {
            format!("; next offset {scanned}")
        } else {
            String::new()
        };
        Ok(format!(
            "{text}[output {id}: {found} line{} with \"{filter}\" in offsets {offset}-{} of {total}{rest}]\n",
            if found == 1 { "" } else { "s" },
            scanned - 1
        ))
    }

    fn keep(&mut self, lines: Vec<Line>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = lines.iter().map(|line| line.text.len()).sum();
        self.bytes += bytes;
        self.kept.push_back(Kept { id, lines, bytes });
        while self.bytes > KEPT_BYTES && self.kept.len() > 1 {
            if let Some(dropped) = self.kept.pop_front() {
                self.bytes -= dropped.bytes;
            }
        }
        id
    }

    fn missing(&self, id: u64) -> String {
        match (self.kept.front(), self.kept.back()) {
            (Some(first), Some(last)) => format!(
                "no output {id} is kept; the server keeps the latest long outputs, now {}-{}",
                first.id, last.id
            ),
            _ => format!("no output {id} is kept; no command result has been long enough to page"),
        }
    }
}

/// The lines from `offset` that fit in a page: at most `limit`, as many as
/// [`PAGE_CHARS`] holds, and always one.
fn page(lines: &[Line], offset: usize, limit: Option<usize>) -> Page {
    let mut text = String::new();
    let mut end = offset;
    for line in lines.iter().skip(offset).take(limit.unwrap_or(usize::MAX)) {
        if end > offset && text.len() + line.text.len() + 1 > PAGE_CHARS {
            break;
        }
        text.push_str(&line.text);
        push_end(&mut text, line, end);
        end += 1;
    }
    Page { text, end }
}

/// Ends the line at offset `at` in `text`, saying where it goes on if it
/// was split.
fn push_end(text: &mut String, line: &Line, at: usize) {
    if line.continues {
        text.push_str(&format!(" [line continues at offset {}]", at + 1));
    }
    text.push('\n');
}

/// `lines` as kept lines, each longer than a page split at character
/// boundaries into pieces that fit one.
fn pieces(lines: &[&str]) -> Vec<Line> {
    let mut kept = Vec::with_capacity(lines.len());
    for line in lines {
        let mut rest = *line;
        while rest.len() > PAGE_CHARS {
            let mut end = PAGE_CHARS;
            while !rest.is_char_boundary(end) {
                end -= 1;
            }
            kept.push(Line {
                text: rest[..end].to_owned(),
                continues: true,
            });
            rest = &rest[end..];
        }
        kept.push(Line {
            text: rest.to_owned(),
            continues: false,
        });
    }
    kept
}

fn joined(lines: &[&str]) -> String {
    let mut text = lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{OutputStore, PAGE_CHARS};

    fn numbered(count: usize, width: usize) -> String {
        (0..count)
            .map(|index| format!("{index:0width$}   \n"))
            .collect()
    }

    /// A result that fits comes back whole, without its trailing padding,
    /// and keeps nothing.
    #[test]
    fn a_short_result_is_whole_and_trimmed() {
        let mut store = OutputStore::default();
        assert_eq!(store.fit("a   \n  b  \n\nc"), "a\n  b\n\nc\n");
        assert!(store.read(0, 0, None, None).is_err());
    }

    /// A long result's pages cover every line once, in order, each within
    /// the page budget, and the last says it is the end.
    #[test]
    fn pages_cover_a_long_result_exactly_once() {
        let mut store = OutputStore::default();
        let text = numbered(10_000, 20);
        let first = store.fit(&text);
        assert!(first.len() <= PAGE_CHARS + 200, "{}", first.len());
        let mut seen: Vec<String> = Vec::new();
        let mut page = first;
        loop {
            let (body, footer) = page.trim_end().rsplit_once('\n').unwrap();
            seen.extend(body.lines().map(str::to_owned));
            let Some((_, next)) = footer.split_once("offset ") else {
                assert!(footer.ends_with("the end]"), "{footer}");
                break;
            };
            let offset: usize = next
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(offset, seen.len(), "{footer}");
            page = store.read(0, offset, None, None).unwrap();
            assert!(page.len() <= PAGE_CHARS + 200);
        }
        let expected: Vec<String> = text
            .lines()
            .map(|line| line.trim_end().to_owned())
            .collect();
        assert_eq!(seen, expected);
    }

    /// A filter finds lines anywhere in the output, ignoring case, each
    /// after the offset that reads around it, and honors a limit.
    #[test]
    fn a_filter_finds_lines_with_their_offsets() {
        let mut store = OutputStore::default();
        let mut text = numbered(5_000, 30);
        text.push_str("nt!NtCreateFile\n");
        store.fit(&text);
        let found = store.read(0, 0, None, Some("ntcreatefile")).unwrap();
        assert!(found.starts_with("5000: nt!NtCreateFile\n"), "{found}");
        assert!(found.contains("1 line with"), "{found}");
        let limited = store.read(0, 0, Some(2), Some("00")).unwrap();
        assert_eq!(
            limited
                .lines()
                .filter(|line| !line.starts_with('['))
                .count(),
            2
        );
        assert!(limited.contains("next offset"), "{limited}");
    }

    /// A line longer than a page is split into pieces at character
    /// boundaries, each read at its own offset, so none of it is lost.
    #[test]
    fn a_line_longer_than_a_page_pages_in_pieces() {
        let mut store = OutputStore::default();
        let long = "\u{e9}".repeat(PAGE_CHARS);
        let first = store.fit(&format!("{long}\nnext\n"));
        assert!(
            first.contains("[line continues at offset 1]"),
            "{}",
            &first[first.len() - 300..]
        );
        assert!(
            first.contains("from offset 1"),
            "{}",
            &first[first.len() - 300..]
        );
        let second = store.read(0, 1, None, None).unwrap();
        assert!(!second.contains("[line continues"), "{second}");
        let third = store.read(0, 2, None, None).unwrap();
        assert!(third.starts_with("next\n"), "{third}");
        let pieces: String = [first, second]
            .iter()
            .map(|page| {
                let line = page.lines().next().unwrap();
                line.split(" [line continues").next().unwrap()
            })
            .collect();
        assert_eq!(pieces, long);
    }

    /// A limit of 0 is refused instead of naming an empty range.
    #[test]
    fn a_limit_of_zero_is_refused() {
        let mut store = OutputStore::default();
        store.fit(&numbered(10_000, 20));
        assert!(store.read(0, 0, Some(0), None).is_err());
        assert!(store.read(0, 5, Some(0), Some("00")).is_err());
        assert!(
            store
                .read(0, 5, Some(1), None)
                .unwrap()
                .contains("offsets 5-5")
        );
    }

    /// Asking for an output that was never kept, or past its end, says
    /// what is there.
    #[test]
    fn a_missing_output_or_offset_says_what_is_kept() {
        let mut store = OutputStore::default();
        store.fit(&numbered(10_000, 20));
        let missing = store.read(7, 0, None, None).unwrap_err();
        assert!(missing.contains("now 0-0"), "{missing}");
        let past = store.read(0, 10_000, None, None).unwrap_err();
        assert!(past.contains("10000 lines"), "{past}");
    }
}
