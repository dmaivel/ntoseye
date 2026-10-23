//! What the interactive prompt tells the terminal besides its text, as escape
//! sequences a terminal that knows them acts on and any other ignores:
//! where each command and its output start and end (OSC 133), a desktop
//! notification of a stop after a long run (OSC 99, OSC 9), and the window
//! title (OSC 2).
//!
//! Only the line editor's prompt on a terminal turns this on
//! ([`begin`]): `--plain-repl`, a capturing host and a redirected stdout
//! get none of it. What a sequence carries from the guest (a symbol, a
//! process name) has its control characters made visible first, so none
//! can end the sequence early.

#[cfg(feature = "cli")]
use std::borrow::Cow;
#[cfg(feature = "cli")]
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::base::output::neutralize_controls;

static ENABLED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "cli")]
/// Turn the sequences on for the line editor's prompt, when stdout is a
/// terminal, and save the window title to give back at [`end`].
pub fn begin() {
    if !std::io::stdout().is_terminal() {
        return;
    }
    ENABLED.store(true, Ordering::SeqCst);
    // XTWINOPS: push the title onto the terminal's stack.
    write("\x1b[22;0t");
}

#[cfg(feature = "cli")]
/// Turn the sequences off as the prompt ends, giving the window its title
/// back.
pub fn end() {
    if !ENABLED.swap(false, Ordering::SeqCst) {
        return;
    }
    write("\x1b[23;0t");
}

#[cfg(feature = "cli")]
/// A semantic prompt mark (OSC 133), which lets a terminal tell commands
/// apart: jump between them, select one's output. reedline writes the
/// prompt's own (`A`, `B`); Tern's field, which draws no prompt in the
/// grid, writes them around the line it echoes.
pub enum PromptMark {
    /// `A`: a prompt starts.
    Prompt,
    /// `B`: the prompt ends, and the typed line starts.
    Input,
    /// `C`: the line's output starts.
    Output,
    /// `D`: the line finished, failed when one of its commands reported an
    /// error.
    Finished { failed: bool },
}

#[cfg(feature = "cli")]
/// Write `mark` to the terminal.
pub fn mark(mark: PromptMark) {
    let text = match mark {
        PromptMark::Prompt => Cow::Borrowed("\x1b]133;A;k=i\x1b\\"),
        PromptMark::Input => Cow::Borrowed("\x1b]133;B\x1b\\"),
        PromptMark::Output => Cow::Borrowed("\x1b]133;C\x1b\\"),
        PromptMark::Finished { failed } => {
            Cow::Owned(format!("\x1b]133;D;{}\x1b\\", u8::from(failed)))
        }
    };
    if ENABLED.load(Ordering::SeqCst) {
        write(&text);
    }
}

/// Ask for a desktop notification of `text`. kitty's own protocol (OSC 99)
/// lets kitty skip it while its window is in view; other terminals read OSC
/// 9, as iTerm2 and Ghostty do.
pub fn notify(text: &str) {
    if !ENABLED.load(Ordering::SeqCst) {
        return;
    }
    let text = neutralize_controls(text);
    if std::env::var_os("KITTY_WINDOW_ID").is_some() {
        write(&format!("\x1b]99;o=invisible;{text}\x1b\\"));
    } else {
        write(&format!("\x1b]9;{text}\x1b\\"));
    }
}

/// Set the window title (OSC 2).
pub fn set_title(title: &str) {
    if ENABLED.load(Ordering::SeqCst) {
        write(&format!("\x1b]2;{}\x1b\\", neutralize_controls(title)));
    }
}

/// Bytes to the terminal, after whatever text is buffered ahead of them.
fn write(sequence: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.flush();
    let _ = stdout.write_all(sequence.as_bytes());
    let _ = stdout.flush();
}
