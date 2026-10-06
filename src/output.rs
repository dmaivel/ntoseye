//! The REPL's stdout seam. Command rendering writes through `out!` /
//! `outln!` instead of `print!`/`println!`, so a host that owns stdout for
//! something else (the stdio MCP transport, which speaks JSON-RPC on it) can
//! run a command and take its text with [`capture`]. With no capture active
//! the macros are plain stdout, so the interactive REPL is unchanged.
//!
//! Capture is thread-local: the REPL and the MCP session actor are each one
//! thread, and a capture installed on one never sees output from another.
//! Transcript logging is process-wide so a `.logopen` command also records
//! diagnostics emitted by the backend or another command context.
//!
//! Styling reaches stdout and stderr only when the stream is a terminal and
//! `NO_COLOR` is unset or empty; a redirected stream gets plain text.

use std::cell::RefCell;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::{LazyLock, Mutex};

thread_local! {
    /// The active captures, innermost last.
    static CAPTURES: RefCell<Vec<Capture>> = const { RefCell::new(Vec::new()) };
}

struct Capture {
    text: Vec<u8>,
    /// Whether errors and warnings land here too, or pass on to an
    /// enclosing capture (or the terminal).
    diagnostics: bool,
    /// An intermediate rendering a caller turns into another form: styling
    /// stays, and the transcript skips it, since the caller logs the output
    /// it finally shows.
    styled: bool,
}

static LOG_SINK: LazyLock<Mutex<Option<std::fs::File>>> = LazyLock::new(|| Mutex::new(None));

static NO_COLOR: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()));
static STDOUT_STYLED: LazyLock<bool> = LazyLock::new(|| !*NO_COLOR && io::stdout().is_terminal());
static STDERR_STYLED: LazyLock<bool> = LazyLock::new(|| !*NO_COLOR && io::stderr().is_terminal());

fn print_stdout(args: fmt::Arguments<'_>) {
    if *STDOUT_STYLED {
        print!("{args}");
    } else {
        print!("{}", strip_ansi(&args.to_string()));
    }
}

fn print_stderr(args: fmt::Arguments<'_>) {
    if *STDERR_STYLED {
        eprint!("{args}");
    } else {
        eprint!("{}", strip_ansi(&args.to_string()));
    }
}

/// Open the command transcript sink. Every subsequent `out!`, `outln!`,
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

/// Append to the innermost capture that takes this kind of text; `false`
/// when none does.
fn append_to_capture(args: fmt::Arguments<'_>, diagnostic: bool) -> bool {
    CAPTURES.with(|stack| {
        let mut stack = stack.borrow_mut();
        let Some(capture) = stack
            .iter_mut()
            .rev()
            .find(|capture| !diagnostic || capture.diagnostics)
        else {
            return false;
        };
        // Vec<u8> writes cannot fail.
        let _ = capture.text.write_fmt(args);
        true
    })
}

/// Backing call for `out!`/`outln!`: append to the active capture, else
/// print to stdout.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    let intermediate = CAPTURES.with(|stack| stack.borrow().last().is_some_and(|c| c.styled));
    if !intermediate {
        log_args(args);
    }
    if !append_to_capture(args, false) {
        print_stdout(args);
    }
}

/// Whether this thread's REPL output goes to a capture rather than the
/// terminal.
pub fn capturing() -> bool {
    CAPTURES.with(|stack| !stack.borrow().is_empty())
}

/// Whether a `.logopen` transcript records the output.
pub fn transcript_open() -> bool {
    LOG_SINK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// Backing call for errors and warnings: append to the innermost capture
/// that takes diagnostics (a capturing host wants everything the user would
/// have seen), else print to stderr or, for `to_stderr == false`, stdout.
pub fn write_diagnostic_fmt(args: fmt::Arguments<'_>, to_stderr: bool) {
    log_args(args);
    if append_to_capture(args, true) {
        return;
    }
    if to_stderr {
        print_stderr(args);
    } else {
        print_stdout(args);
    }
}

/// Backing call for diagnostics that intentionally use stderr on a terminal.
/// It still participates in the transcript sink, while preserving stderr as
/// the visible channel outside a captured host.
pub fn write_stderr_fmt(args: fmt::Arguments<'_>) {
    log_args(args);
    print_stderr(args);
}

/// `print!` that honors an active [`capture`].
#[cfg_attr(not(feature = "repl"), allow(unused_macros))]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::write_fmt(format_args!($($arg)*))
    };
}

/// `println!` that honors an active [`capture`].
macro_rules! outln {
    () => {
        $crate::output::write_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// Drops the captures from its depth on, so a panic unwinding out of `f`
/// (e.g. a Python exception converted at the boundary) cannot leave a stale
/// buffer swallowing the REPL's output.
struct Restore(usize);

impl Drop for Restore {
    fn drop(&mut self) {
        CAPTURES.with(|stack| stack.borrow_mut().truncate(self.0));
    }
}

fn capture_with<R>(diagnostics: bool, styled: bool, f: impl FnOnce() -> R) -> (R, String) {
    let depth = CAPTURES.with(|stack| {
        let mut stack = stack.borrow_mut();
        stack.push(Capture {
            text: Vec::new(),
            diagnostics,
            styled,
        });
        stack.len() - 1
    });
    let restore = Restore(depth);
    let result = f();
    let text = CAPTURES
        .with(|stack| stack.borrow_mut().drain(depth..).next())
        .map(|capture| capture.text)
        .unwrap_or_default();
    drop(restore);
    let text = String::from_utf8_lossy(&text);
    let text = if styled {
        text.into_owned()
    } else {
        strip_ansi(&text)
    };
    (result, text)
}

/// Run `f` with this thread's REPL output, errors and warnings included,
/// captured instead of printed. Returns `f`'s result and the captured text
/// with terminal styling (ANSI CSI sequences) stripped, since a capturing
/// host is never a terminal.
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_with(true, false, f)
}

/// [`capture`] for a command whose output is data, not for the user
/// (`.foreach`'s InCommands): errors and warnings skip this capture and
/// reach whatever would have shown them without it.
pub fn capture_output<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_with(false, false, f)
}

/// [`capture_output`] that keeps the styling and leaves the transcript out:
/// for a renderer that turns existing text output into another form, such
/// as Tern-native spans, and logs what it finally shows itself.
pub fn capture_styled<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_with(false, true, f)
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
    fn capture_output_passes_diagnostics_to_the_enclosing_capture() {
        let (_, outer) = capture(|| {
            let (_, inner) = capture_output(|| {
                outln!("data");
                write_diagnostic_fmt(format_args!("error: bad\n"), true);
                let (_, innermost) =
                    capture(|| write_diagnostic_fmt(format_args!("warning: kept\n"), false));
                assert_eq!(innermost, "warning: kept\n");
            });
            assert_eq!(inner, "data\n");
        });
        assert_eq!(outer, "error: bad\n");
    }

    #[test]
    fn strip_ansi_handles_osc_and_lone_escape() {
        assert_eq!(strip_ansi("a\x1b]0;title\x07b"), "ab");
        assert_eq!(strip_ansi("a\x1b]0;title\x1b\\b"), "ab");
        assert_eq!(strip_ansi("a\x1b"), "a");
        assert_eq!(strip_ansi("plain"), "plain");
    }
}
