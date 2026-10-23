//! What the interactive prompt tells the terminal besides its text, as escape
//! sequences a terminal that knows them acts on and any other ignores:
//! where each command and its output start and end (OSC 133), a desktop
//! notification of a stop after a long run (OSC 99, OSC 9), the window title
//! (OSC 2), and the progress of a run or a long task (OSC 9;4).
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
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use indicatif::WeakProgressBar;

#[cfg(feature = "cli")]
use crate::base::output;
use crate::base::output::neutralize_controls;

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Whether progress is reported: not in Tern, which shows a run and the
/// tasks' bars itself.
static REPORT_PROGRESS: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "cli")]
/// Turn the sequences on for the line editor's prompt, when stdout is a
/// terminal: save the window title, to give back at [`end`], and report
/// progress if `report_progress`.
pub fn begin(report_progress: bool) {
    if !std::io::stdout().is_terminal() {
        return;
    }
    ENABLED.store(true, Ordering::SeqCst);
    // XTWINOPS: push the title onto the terminal's stack.
    write("\x1b[22;0t");
    if report_progress {
        REPORT_PROGRESS.store(true, Ordering::SeqCst);
        output::set_progress_observer(follow_task);
    }
}

#[cfg(feature = "cli")]
/// Turn the sequences off as the prompt ends: no progress is left showing,
/// and the window gets its title back.
pub fn end() {
    if !ENABLED.swap(false, Ordering::SeqCst) {
        return;
    }
    if REPORT_PROGRESS.swap(false, Ordering::SeqCst) {
        let mut progress = progress();
        progress.running = false;
        progress.tasks.clear();
        progress.shown = None;
        drop(progress);
        write("\x1b]9;4;0\x1b\\");
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

/// What the progress sequence (OSC 9;4) shows: a run of the target, which
/// has no end to measure, and the tasks the user waits on.
struct Progress {
    running: bool,
    tasks: Vec<WeakProgressBar>,
    /// Whether a thread is reporting it.
    polling: bool,
    /// What was last sent, to clear once nothing is left.
    shown: Option<(u8, u64)>,
}

static PROGRESS: Mutex<Progress> = Mutex::new(Progress {
    running: false,
    tasks: Vec::new(),
    polling: false,
    shown: None,
});

fn progress() -> MutexGuard<'static, Progress> {
    PROGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How often the progress is sent again: Ghostty drops a state not renewed
/// within about 15 seconds.
const PROGRESS_TICK: Duration = Duration::from_millis(500);

/// Every this many ticks an unchanged state is sent again.
const PROGRESS_RENEW_TICKS: u32 = 4;

/// Show that the target runs, or no longer does.
pub fn set_running(running: bool) {
    if !REPORT_PROGRESS.load(Ordering::SeqCst) {
        return;
    }
    progress().running = running;
    poll_progress();
}

#[cfg(feature = "cli")]
/// Follow a long task's progress bar until it finishes or is dropped: the
/// REPL's [`output::set_progress_observer`].
fn follow_task(bar: WeakProgressBar, _label: &'static str) {
    if !REPORT_PROGRESS.load(Ordering::SeqCst) {
        return;
    }
    progress().tasks.push(bar);
    poll_progress();
}

/// Start the thread that reports the progress, unless one runs: it sends
/// the state at once, then on each change and every two seconds, and stops
/// once it has cleared it.
fn poll_progress() {
    {
        let mut progress = progress();
        if progress.polling {
            return;
        }
        progress.polling = true;
    }
    std::thread::spawn(|| {
        let mut ticks = 0;
        loop {
            let mut progress = progress();
            progress
                .tasks
                .retain(|task| task.upgrade().is_some_and(|bar| !bar.is_finished()));
            // A task's bar, all of them as one; else a run, which has no
            // end to measure (`3`, indeterminate); else nothing (`0`).
            let (length, position) = progress
                .tasks
                .iter()
                .filter_map(WeakProgressBar::upgrade)
                .fold((0, 0), |(length, position), bar| {
                    (
                        length + bar.length().unwrap_or(0),
                        position + bar.position(),
                    )
                });
            let state = match (length, progress.tasks.is_empty(), progress.running) {
                (0, false, _) | (_, true, true) => Some((3, 0)),
                (length, false, _) => Some((1, (position * 100 / length).min(100))),
                (_, true, false) => None,
            };
            let renew = ticks % PROGRESS_RENEW_TICKS == 0;
            match state {
                Some((kind, percent)) if renew || progress.shown != state => {
                    write(&format!("\x1b]9;4;{kind};{percent}\x1b\\"));
                    progress.shown = Some((kind, percent));
                }
                Some(_) => {}
                None => {
                    if progress.shown.take().is_some() {
                        write("\x1b]9;4;0\x1b\\");
                    }
                    progress.polling = false;
                    return;
                }
            }
            drop(progress);
            ticks += 1;
            std::thread::sleep(PROGRESS_TICK);
        }
    });
}

/// Bytes to the terminal, after whatever text is buffered ahead of them.
fn write(sequence: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.flush();
    let _ = stdout.write_all(sequence.as_bytes());
    let _ = stdout.flush();
}
