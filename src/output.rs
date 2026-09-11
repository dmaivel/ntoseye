//! The REPL's stdout seam. Command rendering writes through [`out!`] /
//! [`outln!`] instead of `print!`/`println!`, so a host that owns stdout for
//! something else (the stdio MCP transport, which speaks JSON-RPC on it) can
//! run a command and take its text with [`capture`]. With no capture active
//! the macros are plain stdout, so the interactive REPL is unchanged.
//!
//! The sink is thread-local: the REPL and the MCP session actor are each one
//! thread, and a capture installed on one never sees output from another.

use std::cell::RefCell;
use std::fmt;
use std::io::Write;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Backing call for [`out!`]/[`outln!`]: append to the active capture, else
/// print to stdout.
pub fn write_fmt(args: fmt::Arguments<'_>) {
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
