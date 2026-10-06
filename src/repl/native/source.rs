//! Source lines as Tern code: highlighted by the file's language, numbered
//! from their real line, the current line marked, under a header naming the
//! file; ⌘-click opens the file at the line in a Tern file block.

use std::path::Path;

use tern_sdk::View;
use tern_sdk::ui::{self, Code, CodeMark, Tone};

use crate::symbols::{LocalSourceState, SourceLocation};

/// The lines a stop shows on each side of its line.
const STOP_CONTEXT: u32 = 3;

/// `lines` of `path`, the first one numbered `first`, with `current` marked.
pub fn listing(path: &Path, lines: &[&str], first: u32, current: Option<u32>) -> Code<()> {
    let at = current.unwrap_or(first);
    let mut code = ui::code(lines.join("\n"))
        // The grammar comes from the file name, as the header shows it.
        .path(path.display().to_string())
        .numbers(true)
        .start(i64::from(first))
        .href(format!("{}:{at}", path.display()));
    if let Some(line) = current {
        code = code.marks(vec![CodeMark {
            line: u64::from(line),
            tone: Some(Tone::Accent),
            ranges: Vec::new(),
        }]);
    }
    code
}

/// `ls`, `lsa`: the listing on its own.
pub fn view(path: &Path, lines: &[&str], first: u32, current: Option<u32>) -> View {
    View::new().main([listing(path, lines, first, current)])
}

/// The lines around a stop's source line, when its file is the one the PDB
/// names and can be read: nothing otherwise, since the stack's source tag
/// already says why.
pub fn around(location: &SourceLocation) -> Option<Code<()>> {
    let local = location.local.as_ref()?;
    if local.state != LocalSourceState::Found {
        return None;
    }
    let text = std::fs::read_to_string(&local.path).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let line = location.line;
    if line == 0 || line as usize > lines.len() {
        return None;
    }
    let first = line.saturating_sub(STOP_CONTEXT).max(1);
    let last = (line + STOP_CONTEXT).min(lines.len() as u32);
    Some(listing(
        &local.path,
        &lines[first as usize - 1..last as usize],
        first,
        Some(line),
    ))
}
