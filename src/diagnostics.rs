use std::fmt::Display;

use owo_colors::OwoColorize;

use crate::output;

pub fn print_error(message: impl Display) {
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
        outln!("{line}");
    }
}

fn print_labeled_stderr(label: &str, styled_label: &str, message: &str) {
    // A capturing host wants everything the user would have seen, errors
    // included; stderr is only the right channel for an actual terminal.
    if output::capturing() {
        return print_labeled_stdout(label, styled_label, message);
    }
    for line in labeled_lines(label, styled_label, message) {
        output::write_stderr_fmt(format_args!("{line}\n"));
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
