use std::cell::Cell;
use std::fmt::Display;

use owo_colors::OwoColorize;

use crate::output;

thread_local! {
    /// Errors reported on this thread. Commands report a failure and return
    /// normally, so a dispatcher compares this count around a command to
    /// tell whether it failed.
    static ERRORS_REPORTED: Cell<u64> = const { Cell::new(0) };
}

/// How many errors this thread has reported.
pub fn errors_reported() -> u64 {
    ERRORS_REPORTED.with(Cell::get)
}

/// Count an error that is shown some other way than [`print_error`].
pub fn note_error() {
    ERRORS_REPORTED.with(|count| count.set(count.get() + 1));
}

pub fn print_error(message: impl Display) {
    note_error();
    print_labeled_stderr(
        "error:",
        &"error:".bright_red().bold().to_string(),
        &message.to_string(),
    );
}

pub fn print_warning(message: impl Display) {
    print_labeled_stdout(
        "warning:",
        &"warning:".bright_magenta().bold().to_string(),
        &message.to_string(),
    );
}

pub fn eprint_warning(message: impl Display) {
    print_labeled_stderr(
        "warning:",
        &"warning:".bright_magenta().bold().to_string(),
        &message.to_string(),
    );
}

pub fn eprint_note(message: impl Display) {
    print_labeled_stderr(
        "note:",
        &"note:".bright_cyan().bold().to_string(),
        &message.to_string(),
    );
}

fn print_labeled_stdout(label: &str, styled_label: &str, message: &str) {
    for line in labeled_lines(label, styled_label, message) {
        output::write_diagnostic_fmt(format_args!("{line}\n"), false);
    }
}

fn print_labeled_stderr(label: &str, styled_label: &str, message: &str) {
    for line in labeled_lines(label, styled_label, message) {
        output::write_diagnostic_fmt(format_args!("{line}\n"), true);
    }
}

fn labeled_lines(label: &str, styled_label: &str, message: &str) -> Vec<String> {
    let mut lines = message.lines();
    let Some(first) = lines.next() else {
        return vec![styled_label.to_string()];
    };

    let indent = " ".repeat(label.len() + 1);
    let mut out = vec![format!("{styled_label} {first}")];
    out.extend(lines.map(|line| format!("{indent}{line}")));
    out
}
