//! Tern, Stencil's terminal: the handshake, the token styles the prompt
//! and the palette color with, and the live surface. Commands print text in
//! every terminal; in Tern the interactive REPL also reads them in Tern's
//! input field ([`super::tern_prompt`]) with its palette, and shows a
//! running target and long tasks' progress as a live `flow` surface. A
//! capturing host (MCP, the Python SDK, DAP's console, `.foreach`),
//! `--plain-repl` and `TERN_TSP=0` get none of it.
//!
//! The live surface is opened with `listen:false`: Tern sends nothing back
//! about it, so the prompt keeps stdin to itself. The one read is the
//! handshake, once, before the first prompt.

pub mod completions;
pub mod palette;

use std::io::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use indicatif::WeakProgressBar;
use tern_sdk::reconcile::Doc;
use tern_sdk::ui::{self, Basis, Bound, Extent, Gap, Row, Span, SpinnerStyle};
use tern_sdk::wire::{self, Close, Encoder, Frame, Message, Open, Sheet};
use tern_sdk::{Capabilities, Mode, Node, Options, Session, View};

use crate::base::diagnostics;
use crate::base::output;

/// What the terminal answered, when it speaks the protocol with flow
/// surfaces.
static CAPABILITIES: OnceLock<Capabilities> = OnceLock::new();
static NEXT_SURFACE: AtomicU64 = AtomicU64::new(1);

/// The surfaces' role: `data-surface` for the stylesheet's selectors.
const ROLE: &str = "ntoseye";
/// Token colors and the marks the kinds don't draw themselves.
pub const STYLESHEET: &str = include_str!("ntoseye.css");

/// Ask the terminal whether it draws Tern surfaces. Called once by the
/// interactive prompt before reedline starts reading, since the answer
/// arrives on stdin; anything but Tern (or no tty, a multiplexer,
/// `TERN_TSP=0`) leaves the text renderers on.
pub fn detect() {
    let Some(session) = connect::<()>() else {
        return;
    };
    let capabilities = session.caps().clone();
    // Closing restores the tty and drains the DA1 answer behind the reply,
    // so it never reaches reedline as typed text.
    if session.close().is_err() {
        return;
    }
    if capabilities.has_feature(wire::feature::FLOW) {
        let _ = CAPABILITIES.set(capabilities);
        output::set_progress_hook(follow_task);
        output::set_text_hook(before_text);
    } else {
        // An update replaces Tern's binary while its session daemon keeps
        // running the old one, which may predate flow surfaces: without
        // this, the text looks like ntoseye ignoring Tern.
        diagnostics::print_warning(format!(
            "Tern {} cannot draw ntoseye's prompt (no flow surfaces), so the line editor is \
             used; update Tern, then use Restart Tern in its command palette",
            capabilities.version
        ));
    }
}

/// A Tern session on the terminal, or `None` when it isn't Tern.
///
/// The SDK's raw mode makes SIGINT, SIGTERM, SIGHUP and SIGQUIT restore the
/// terminal and kill the process, which would skip the teardown that removes
/// breakpoints and resumes the guest; ntoseye's own handlers go back in
/// place, and the session's close restores them again. A SIGTERM while a
/// session is open on a live terminal can then leave the terminal raw, since
/// the teardown wakes the reader by replacing stdin; the guest matters more.
pub fn connect<M>() -> Option<Session<M>> {
    connect_with(&[], false)
}

/// [`connect`], listing program `features` in the hello (`edit` for Tern's
/// native editing in a field), with bracketed `paste` when asked: a paste
/// then arrives as one key rather than as typed keys.
pub fn connect_with<M>(features: &[&str], paste: bool) -> Option<Session<M>> {
    let mut options = Options::new()
        .app("ntoseye")
        .version(env!("CARGO_PKG_VERSION"))
        .bracketed_paste(paste)
        .kitty_keyboard(false);
    for feature in features {
        options = options.feature(*feature);
    }
    let handlers = SignalHandlers::save();
    let session = Session::<M>::connect(options).ok().flatten();
    handlers.restore();
    session
}

/// The dispositions of the signals the SDK's raw mode takes over.
struct SignalHandlers {
    #[cfg(unix)]
    saved: Vec<(libc::c_int, libc::sigaction)>,
}

impl SignalHandlers {
    #[cfg(unix)]
    const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

    fn save() -> Self {
        #[cfg(unix)]
        {
            let saved = Self::SIGNALS
                .into_iter()
                .filter_map(|signal| {
                    // SAFETY: a zeroed sigaction is valid; a null action only
                    // reads the current disposition into `old`.
                    unsafe {
                        let mut old: libc::sigaction = std::mem::zeroed();
                        (libc::sigaction(signal, std::ptr::null(), &mut old) == 0)
                            .then_some((signal, old))
                    }
                })
                .collect();
            Self { saved }
        }
        #[cfg(not(unix))]
        Self {}
    }

    fn restore(self) {
        #[cfg(unix)]
        for (signal, action) in &self.saved {
            // SAFETY: puts back a disposition sigaction returned.
            unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
        }
    }
}

/// Whether this output reaches a Tern pane: the handshake succeeded and no
/// host is capturing the text.
pub fn active() -> bool {
    CAPABILITIES.get().is_some() && !output::capturing()
}

/// Show that the target runs until the next result: a spinner and a timer
/// Tern clocks itself, in place of the line `text` prints.
pub fn running(text: impl FnOnce()) {
    let Some(capabilities) = drawing() else {
        return text();
    };
    let mut live = live();
    live.started = Some(Instant::now());
    if live.show(capabilities).is_err() {
        live.started = None;
        return text();
    }
    if output::transcript_open() {
        let _ = output::capture_output(text);
    }
}

/// End the live surface: the running indicator stops at how long the target
/// ran and stays in the scrollback, and tasks' progress bars go.
pub fn finish_running() {
    let mut live = live();
    live.tasks.clear();
    let Some(started) = live.started.take() else {
        live.end();
        return;
    };
    let ran = View::new().main([ran_row(started.elapsed())]);
    live.end_with(ran);
}

/// `ran 1.4s`: a run's frozen timer.
pub fn ran_row(ran: Duration) -> Row<()> {
    ui::row()
        .gap(Gap::Sm)
        .child(ui::text([span("ran", MUTED)]))
        .child(ui::elapsed().stopped(u64::try_from(ran.as_millis()).unwrap_or(u64::MAX)))
}

/// Follow a long task's progress bar in the live surface until it finishes
/// or is dropped: the REPL's [`output::progress_bar`] hook. One poller
/// redraws every bar shown at once, such as parallel downloads.
fn follow_task(bar: WeakProgressBar, label: &'static str) {
    {
        let mut state = live();
        state.tasks.push(Task { bar, label });
        if state.polling {
            return;
        }
        state.polling = true;
    }
    std::thread::spawn(move || {
        loop {
            // A first tick before drawing, so a quick task never flashes.
            std::thread::sleep(TASK_TICK);
            let mut live = live();
            live.tasks
                .retain(|task| task.bar.upgrade().is_some_and(|bar| !bar.is_finished()));
            if let Some(capabilities) = CAPABILITIES.get() {
                let _ = live.show(capabilities);
            }
            if live.tasks.is_empty() {
                live.polling = false;
                return;
            }
        }
    });
}

/// How often a task's bar is redrawn.
const TASK_TICK: Duration = Duration::from_millis(100);

/// Before text is printed: when the live surface shows only bars that have
/// finished, it goes now rather than at the poller's next tick, so the text
/// (a task's summary, say) takes its row instead of leaving it blank.
fn before_text() {
    let mut live = live();
    if live.shown.is_none() || live.started.is_some() {
        return;
    }
    if live
        .tasks
        .iter()
        .all(|task| task.bar.upgrade().is_none_or(|bar| bar.is_finished()))
    {
        live.tasks.clear();
        live.end();
    }
}

/// The one surface left open while ntoseye works: Tern keeps a single live
/// flow surface per screen, so the running indicator and the tasks' progress
/// share it, and anything drawn after ends it first.
struct Live {
    shown: Option<Shown>,
    /// When the target was resumed, while it runs.
    started: Option<Instant>,
    tasks: Vec<Task>,
    /// Whether a thread is redrawing the tasks.
    polling: bool,
}

/// The open surface, the document it shows and its last frame's number.
struct Shown {
    surface: Surface,
    doc: Doc,
    sequence: u64,
    /// [`output::printed`] when it opened.
    printed: u64,
}

struct Task {
    bar: WeakProgressBar,
    /// What the row says when the bar has no message of its own.
    label: &'static str,
}

static LIVE: Mutex<Live> = Mutex::new(Live {
    shown: None,
    started: None,
    tasks: Vec::new(),
    polling: false,
});

fn live() -> std::sync::MutexGuard<'static, Live> {
    LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Live {
    /// The running indicator and the task's bar, or nothing to show.
    fn view(&self) -> Option<View> {
        let mut rows: Vec<Node> = Vec::new();
        if self.started.is_some() {
            rows.push(
                ui::row()
                    .gap(Gap::Sm)
                    .child(
                        ui::spinner()
                            .style(SpinnerStyle::Orbit)
                            .label([span("running", MUTED)]),
                    )
                    .child(ui::elapsed())
                    .child(ui::kbd(["Ctrl", "C"]))
                    .child(ui::text([span("to pause", DIM)]))
                    .into(),
            );
        }
        for task in &self.tasks {
            let Some(bar) = task.bar.upgrade() else {
                continue;
            };
            let message = bar.message();
            let label = match message.trim() {
                "" => task.label,
                message => message,
            };
            rows.push(task_row(label, bar.position(), bar.length()).into());
        }
        (!rows.is_empty())
            .then(|| View::new().main([ui::col().role("ntoseye.live").children(rows)]))
    }

    /// Bring the surface up to date: open it, send the difference, or close
    /// it when there is nothing left to show.
    fn show(&mut self, capabilities: &Capabilities) -> Result<(), tern_sdk::Error> {
        let Some(view) = self.view() else {
            self.end();
            return Ok(());
        };
        let doc = Doc::from_view(view)?;
        match &mut self.shown {
            Some(shown) => {
                if shown.doc != doc {
                    shown.sequence += 1;
                    write(&shown.surface.next(shown.sequence, &shown.doc, &doc)?);
                    shown.doc = doc;
                }
            }
            None => {
                let surface = Surface::new(capabilities);
                write(&surface.open(&doc)?);
                self.shown = Some(Shown {
                    surface,
                    doc,
                    sequence: 1,
                    printed: output::printed(),
                });
            }
        }
        Ok(())
    }

    /// Remove the surface from the pane. Its anchor row stays, empty, with
    /// the cursor below it: when nothing was printed there since, the cursor
    /// goes back up so the next output takes the row instead of leaving a
    /// blank line.
    fn end(&mut self) {
        if let Some(shown) = self.shown.take()
            && let Ok(mut bytes) = shown.surface.close(false)
        {
            if shown.printed == output::printed() {
                bytes.extend_from_slice(b"\x1b[A\r");
            }
            write(&bytes);
        }
    }

    /// Leave `last` in the scrollback in place of the surface.
    fn end_with(&mut self, last: View) {
        let Some(shown) = self.shown.take() else {
            return;
        };
        let Ok(doc) = Doc::from_view(last) else {
            return;
        };
        let mut bytes = shown
            .surface
            .next(shown.sequence + 1, &shown.doc, &doc)
            .unwrap_or_default();
        bytes.extend(shown.surface.close(true).unwrap_or_default());
        write(&bytes);
    }
}

/// `indexing symbols ━━━━━━──── 2/4`, or a spinner while the length is
/// unknown.
fn task_row(label: &str, position: u64, length: Option<u64>) -> Row<()> {
    let row = ui::row().gap(Gap::Sm).child(ui::text([span(label, MUTED)]));
    match length.filter(|&length| length > 0) {
        Some(length) => row
            .child(
                ui::progress()
                    .value(position.min(length) as f64 / length as f64)
                    .basis(Basis::Content)
                    .min(Bound::w(Extent::Ch(24.0))),
            )
            .child(ui::text([span(format!("{position}/{length}"), NUMBER)])),
        None => row.child(ui::spinner().style(SpinnerStyle::Orbit)),
    }
}

/// The capabilities, when this output reaches a Tern pane.
fn drawing() -> Option<&'static Capabilities> {
    CAPABILITIES.get().filter(|_| !output::capturing())
}

/// Bytes to the terminal, after whatever text is buffered ahead of them.
fn write(bytes: &[u8]) {
    let mut stdout = io::stdout().lock();
    let _ = stdout.flush();
    let _ = stdout.write_all(bytes);
    let _ = stdout.flush();
}

/// One `flow` surface that never listens: Tern sends nothing back, so its
/// frames need no acknowledgment.
struct Surface {
    id: String,
    limit: usize,
    styles: bool,
}

impl Surface {
    fn new(capabilities: &Capabilities) -> Self {
        Self {
            id: format!("{ROLE}{}", NEXT_SURFACE.fetch_add(1, Ordering::Relaxed)),
            limit: match capabilities.apc {
                0 => wire::APC_LIMIT,
                apc => apc,
            },
            styles: capabilities.has_feature(wire::feature::STYLES),
        }
    }

    /// Open it, its stylesheet, and the first frame adding `doc`.
    fn open(&self, doc: &Doc) -> Result<Vec<u8>, tern_sdk::Error> {
        let mut encoder = Encoder::new(self.limit);
        let mut bytes = encoder.encode(&Message::Open(Open {
            id: self.id.clone(),
            mode: Some(Mode::Flow),
            role: Some(ROLE.into()),
            listen: Some(false),
            ..Open::default()
        }))?;
        if self.styles {
            bytes.extend(encoder.encode(&Message::Sheet(Sheet {
                sf: Some(self.id.clone()),
                name: ROLE.into(),
                css: Some(STYLESHEET.into()),
            }))?);
        }
        bytes.extend(self.frame(&mut encoder, 1, &Doc::default(), doc)?);
        Ok(bytes)
    }

    /// Frame `sequence`, turning `from` into `to`.
    fn next(&self, sequence: u64, from: &Doc, to: &Doc) -> Result<Vec<u8>, tern_sdk::Error> {
        self.frame(&mut Encoder::new(self.limit), sequence, from, to)
    }

    fn frame(
        &self,
        encoder: &mut Encoder,
        sequence: u64,
        from: &Doc,
        to: &Doc,
    ) -> Result<Vec<u8>, tern_sdk::Error> {
        encoder.encode(&Message::Frame(Frame {
            sf: self.id.clone(),
            s: sequence,
            ops: from.ops(to, &self.id),
        }))
    }

    /// Close it: kept in the scrollback as output, or removed.
    fn close(&self, keep: bool) -> Result<Vec<u8>, tern_sdk::Error> {
        Encoder::new(self.limit).encode(&Message::Close(Close {
            id: self.id.clone(),
            keep,
        }))
    }
}

// ---------------------------------------------------------------------------
// The design system: ntoseye's palette (`crate::hosts::ui`) as Tern span tokens.
// Semantic tokens take Tern's theme colors; the `nt*` tokens are colored
// from Tern's syntax palette by the stylesheet, so code reads like Tern's
// own highlighting.
// ---------------------------------------------------------------------------

/// Secondary text: labels, offsets, notes.
pub const MUTED: &str = "muted";
/// Quieter than muted: instruction bytes, separators.
pub const DIM: &str = "dim";
/// Values: register contents, counts, ids.
pub const NUMBER: &str = "num";
/// A resolved function name.
pub const SYMBOL: &str = "ntSymbol";
/// An instruction mnemonic.
pub const MNEMONIC: &str = "ntMnemonic";
/// A register name inside an instruction.
pub const REGISTER: &str = "ntRegister";
/// A quoted string.
pub const STRING: &str = "ntString";

/// A span of `text` in `style` (space-separated tokens; empty is plain).
pub fn span(text: impl Into<String>, style: &str) -> Span {
    let span = ui::span(text);
    if style.is_empty() {
        span
    } else {
        span.style(style)
    }
}
