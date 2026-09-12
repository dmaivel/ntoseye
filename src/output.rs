//! The REPL's stdout seam. Command rendering writes through [`out!`] /
//! [`outln!`] instead of `print!`/`println!`, so a host that owns stdout for
//! something else (the stdio MCP transport, which speaks JSON-RPC on it) can
//! run a command and take its text with [`capture`]. With no capture active
//! the macros are plain stdout, so the interactive REPL is unchanged.
//!
//! Capture is thread-local: the REPL and the MCP session actor are each one
//! thread, and a capture installed on one never sees output from another.
//! Transcript logging is process-wide so a `.logopen` command also records
//! diagnostics emitted by the backend or another command context.

use std::cell::RefCell;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{LazyLock, Mutex};

thread_local! {
    static CAPTURE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

static LOG_SINK: LazyLock<Mutex<Option<std::fs::File>>> = LazyLock::new(|| Mutex::new(None));

/// Open the command transcript sink. Every subsequent [`out!`], [`outln!`],
/// and diagnostic emission is copied here with terminal escape sequences
/// removed. Opening a new sink replaces the previous one.
pub fn open_log(path: impl AsRef<Path>, append: bool) -> io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(!append)
        .append(append)
        .open(path)?;
    let mut sink = LOG_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *sink = Some(file);
    Ok(())
}

/// Close the command transcript sink, flushing it first when possible.
pub fn close_log() {
    let mut sink = LOG_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(mut file) = sink.take() {
        let _ = file.flush();
    }
}

fn log_text(text: &str) {
    let mut sink = LOG_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(file) = sink.as_mut() else {
        return;
    };
    // A failed transcript must never interfere with debugger output. Keep the
    // sink installed so a transient error does not silently redirect later
    // output elsewhere, and flush each write so `.logclose` is optional.
    let _ = file.write_all(text.as_bytes());
    let _ = file.flush();
}

fn log_args(args: fmt::Arguments<'_>) {
    let mut sink = LOG_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(file) = sink.as_mut() else {
        return;
    };
    let mut text = String::new();
    let _ = fmt::write(&mut text, args);
    let clean = strip_ansi(&text);
    let _ = file.write_all(clean.as_bytes());
    let _ = file.flush();
}

/// Record one command line in the active transcript without echoing it to the
/// terminal or a capture buffer. The REPL owns the prompt itself, so the
/// transcript uses a plain `> ` prompt that remains useful in redirected logs.
pub fn log_input_line(line: &str) {
    let mut text = String::with_capacity(line.len() + 3);
    text.push_str("> ");
    text.push_str(line);
    text.push('\n');
    let clean = strip_ansi(&text);
    log_text(&clean);
}

/// Backing call for [`out!`]/[`outln!`]: append to the active capture, else
/// print to stdout.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    log_args(args);
    let captured = CAPTURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(buf) = slot.as_mut() else {
            return false;
        };
        // Vec<u8> writes cannot fail.
        let _ = buf.write_fmt(args);
        true
    });
    if !captured {
        print!("{args}");
    }
}

/// Backing call for diagnostics that intentionally use stderr on a terminal.
/// It still participates in the transcript sink, while preserving stderr as
/// the visible channel outside a captured host.
pub fn write_stderr_fmt(args: fmt::Arguments<'_>) {
    log_args(args);
    eprint!("{args}");
}

/// Whether this thread's REPL output is currently being captured.
pub fn capturing() -> bool {
    CAPTURE.with(|slot| slot.borrow().is_some())
}

/// `print!` that honours an active [`capture`].
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::write_fmt(format_args!($($arg)*))
    };
}

/// `println!` that honours an active [`capture`].
macro_rules! outln {
    () => {
        $crate::output::write_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Restores the previous capture slot on drop, so a panic unwinding out of
/// `f` (e.g. a Python exception converted at the boundary) cannot leave a
/// stale buffer swallowing the REPL's output.
struct Restore(Option<Vec<u8>>);

impl Drop for Restore {
    fn drop(&mut self) {
        CAPTURE.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}

/// Run `f` with this thread's REPL output captured instead of printed.
/// Returns `f`'s result and the captured text with terminal styling (ANSI
/// CSI sequences) stripped, since a capturing host is never a terminal.
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, String) {
    let previous = CAPTURE.with(|slot| slot.borrow_mut().replace(Vec::new()));
    let restore = Restore(previous);
    let result = f();
    let buf = CAPTURE
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    drop(restore);
    (result, strip_ansi(&String::from_utf8_lossy(&buf)))
}

/// Remove ANSI escape sequences: CSI (`ESC [ … final`) and OSC (`ESC ] … BEL`
/// / `ESC \`), which is everything `owo_colors` emits.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                // Parameter/intermediate bytes 0x20..=0x3F, then one final
                // byte 0x40..=0x7E.
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                let mut prev = '\0';
                for c in chars.by_ref() {
                    if c == '\x07' || (prev == '\x1b' && c == '\\') {
                        break;
                    }
                    prev = c;
                }
            }
            // A lone ESC or an unknown sequence introducer: drop the ESC and
            // keep going with whatever followed.
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use owo_colors::OwoColorize;

    #[test]
    fn capture_collects_and_strips_styling() {
        let (value, text) = capture(|| {
            outln!("{} {}", "bold".bold(), "red".bright_red());
            out!("tail");
            7
        });
        assert_eq!(value, 7);
        assert_eq!(text, "bold red\ntail");
    }

    #[test]
    fn captures_nest_and_restore() {
        let (_, outer) = capture(|| {
            outln!("before");
            let (_, inner) = capture(|| outln!("inner"));
            assert_eq!(inner, "inner\n");
            outln!("after");
        });
        assert_eq!(outer, "before\nafter\n");
    }

    #[test]
    fn strip_ansi_handles_osc_and_lone_escape() {
        assert_eq!(strip_ansi("a\x1b]0;title\x07b"), "ab");
        assert_eq!(strip_ansi("a\x1b]0;title\x1b\\b"), "ab");
        assert_eq!(strip_ansi("a\x1b"), "a");
        assert_eq!(strip_ansi("plain"), "plain");
    }
}
