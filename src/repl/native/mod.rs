//! Tern-native output. In Tern, Stencil's terminal, the interactive REPL
//! draws a command's result as Tern Surface Protocol nodes (cards, tables,
//! trees) that Tern lays out, themes and folds, instead of as text. Every
//! other terminal, a capturing host (MCP, the Python SDK, DAP's console,
//! `.foreach`), `--plain-repl` and `TERN_TSP=0` get the text renderers
//! unchanged, so each converted command keeps both.
//!
//! A result is a `flow` surface opened with `listen:false`: it stays in the
//! scrollback like output, and Tern sends nothing back about it, so reedline
//! keeps stdin to itself. The one read is the handshake, once, before the
//! first prompt.

pub mod analyze;
pub mod browser;
pub mod bugcheck;
pub mod code;
pub mod frames;
pub mod help;
pub mod inspect;
pub mod lists;
pub mod memory;
pub mod palette;
pub mod session;
pub mod source;
pub mod stack;
pub mod stop;
pub mod trees;
pub mod types;

use std::io::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use indicatif::WeakProgressBar;
use tern_sdk::reconcile::Doc;
use tern_sdk::ui::{self, Basis, Bound, Extent, Gap, Row, Span, SpinnerStyle, TextNode, Wrap};
use tern_sdk::wire::{self, Close, Encoder, Frame, Message, Open, Sheet};
use tern_sdk::{Capabilities, Mode, Node, Options, Session, View};

use crate::diagnostics;
use crate::output;

/// What the terminal answered, when it speaks the protocol with flow
/// surfaces.
static CAPABILITIES: OnceLock<Capabilities> = OnceLock::new();
static NEXT_SURFACE: AtomicU64 = AtomicU64::new(1);

/// The surfaces' role: `data-surface` for the stylesheet's selectors.
const ROLE: &str = "ntoseye";
/// Token colors and the marks the kinds don't draw themselves.
const STYLESHEET: &str = include_str!("ntoseye.css");

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
            "Tern {} cannot draw ntoseye's views (no flow surfaces), so output stays text; \
             update Tern, then use Restart Tern in its command palette",
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
    let options = Options::new()
        .app("ntoseye")
        .version(env!("CARGO_PKG_VERSION"))
        .bracketed_paste(false)
        .kitty_keyboard(false);
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

/// Show a result: `view` in Tern, else the text `text` prints. A `.logopen`
/// transcript gets the text either way, so the text renderer must not
/// change state the native path skips.
pub fn render(view: impl FnOnce() -> View, text: impl FnOnce()) {
    let Some(capabilities) = drawing() else {
        return text();
    };
    let bytes = Doc::from_view(view()).and_then(|doc| {
        let mut live = live();
        live.tasks.clear();
        // A result that didn't take the run leaves it in the scrollback.
        if let Some(started) = live.started.take() {
            live.end_with(View::new().main([ran_row(started.elapsed())]));
        }
        // The live surface becomes the result, so nothing is left where it
        // was: unless text was printed since it opened, which would then
        // show below the result.
        match live.shown.take() {
            Some(shown) if shown.printed == output::printed() => {
                let mut bytes = shown.surface.next(shown.sequence + 1, &shown.doc, &doc)?;
                bytes.extend(shown.surface.close(true)?);
                Ok(bytes)
            }
            shown => {
                if let Some(shown) = shown {
                    write(&shown.surface.close(false)?);
                }
                Surface::new(capabilities).closed(&doc)
            }
        }
    });
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics::print_warning(format!("Tern view failed ({error}); showing text"));
            return text();
        }
    };
    if output::transcript_open() {
        // Run into a capture only to log: the capture swallows the text.
        let _ = output::capture_output(text);
    }
    write(&bytes);
}

/// Text only the text renderer shows, such as the blank line that sets a
/// stop apart from the output above it: a native view brings its own
/// spacing. A `.logopen` transcript still records it.
pub fn omit(text: impl FnOnce()) {
    if drawing().is_none() {
        return text();
    }
    if output::transcript_open() {
        let _ = output::capture_output(text);
    }
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

/// How long the target ran, for a view that shows the run itself, such as
/// the stop card; the running indicator then turns into that view. `None`
/// when the target wasn't running.
pub fn take_run() -> Option<Duration> {
    live().started.take().map(|started| started.elapsed())
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

    /// Open it with `doc` and close it at once, kept as output.
    fn closed(&self, doc: &Doc) -> Result<Vec<u8>, tern_sdk::Error> {
        let mut bytes = self.open(doc)?;
        bytes.extend(self.close(true)?);
        Ok(bytes)
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
// The design system: ntoseye's palette (`crate::ui`) as Tern span tokens.
// Semantic tokens take Tern's theme colors; the `nt*` tokens are colored
// from Tern's syntax palette by the stylesheet, so code reads like Tern's
// own highlighting.
// ---------------------------------------------------------------------------

/// Secondary text: labels, offsets, notes.
pub const MUTED: &str = "muted";
/// Quieter than muted: instruction bytes, separators.
pub const DIM: &str = "dim";
/// Emphasis in the primary text color.
pub const STRONG: &str = "strong";
/// Values: register contents, counts, ids.
pub const NUMBER: &str = "num";
/// A resolved function name.
pub const SYMBOL: &str = "ntSymbol";
/// An instruction mnemonic.
pub const MNEMONIC: &str = "ntMnemonic";
/// A register name inside an instruction.
pub const REGISTER: &str = "ntRegister";
/// An immediate or displacement inside an instruction.
pub const IMMEDIATE: &str = "ntNumber";
/// A type name.
pub const TYPE: &str = "ntType";
/// A value that changed since the target last stopped, such as a register a
/// step wrote: the warning color, as the text renderer's yellow.
pub const CHANGED: &str = "warning";

/// A span of `text` in `style` (space-separated tokens; empty is plain).
pub fn span(text: impl Into<String>, style: &str) -> Span {
    let span = ui::span(text);
    if style.is_empty() {
        span
    } else {
        span.style(style)
    }
}

/// An absolute address, 16 digits like the text renderers print it.
pub fn addr(value: u64) -> Span {
    ui::span(format!("{value:016x}"))
}

/// `module!function+0x1d`: the module quiet, the function the anchor, the
/// offset quiet. `module+0x5d4de8` (no function) keeps the module plain,
/// and a raw `0x…` (nothing resolved) is all quiet.
pub fn symbol(symbol: &str) -> Vec<Span> {
    if symbol.starts_with("0x") || symbol.is_empty() {
        return vec![span(symbol, MUTED)];
    }
    let (body, offset) = match symbol.rfind("+0x") {
        Some(at) => symbol.split_at(at),
        None => (symbol, ""),
    };
    let mut spans = Vec::with_capacity(3);
    match body.split_once('!') {
        Some((module, function)) => {
            spans.push(span(format!("{module}!"), MUTED));
            spans.push(span(function, SYMBOL));
        }
        None => spans.push(span(body, "")),
    }
    if !offset.is_empty() {
        spans.push(span(offset, MUTED));
    }
    spans
}

/// Text that the text renderers styled, as spans: ntoseye's few colors
/// become the tokens of the same meaning, so a native view can reuse any
/// existing formatter without a second palette.
pub fn spans(styled: &str) -> Vec<Span> {
    let mut out = Vec::new();
    let mut style = Sgr::default();
    let mut run = String::new();
    let mut rest = styled;
    while let Some(at) = rest.find('\x1b') {
        run.push_str(&rest[..at]);
        rest = &rest[at..];
        // CSI: ESC [ parameters final. Only `m` (SGR) carries style; any
        // other sequence, or a stray ESC, is dropped.
        let Some(body) = rest.strip_prefix("\x1b[") else {
            rest = &rest[1..];
            continue;
        };
        let end = body
            .find(|c: char| ('\x40'..='\x7e').contains(&c))
            .unwrap_or(body.len());
        let next = style.apply(&body[..end], body[end..].starts_with('m'));
        if next != style && !run.is_empty() {
            out.push(span(std::mem::take(&mut run), &style.tokens()));
        }
        style = next;
        rest = body.get(end + 1..).unwrap_or("");
    }
    run.push_str(rest);
    if !run.is_empty() {
        out.push(span(run, &style.tokens()));
    }
    out
}

/// Multi-line output of a text renderer as one block, its columns kept.
pub fn block(styled: &str) -> TextNode<()> {
    ui::text(spans(styled.trim_end_matches('\n'))).wrap(Wrap::None)
}

/// What `print` writes, styled, without printing it or logging it: for a
/// native view that reuses a text renderer's formatting.
pub fn styled(print: impl FnOnce()) -> String {
    output::capture_styled(print).1
}

/// The SGR state that matters for tokens.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Sgr {
    color: Option<&'static str>,
    bold: bool,
    dim: bool,
}

impl Sgr {
    fn apply(mut self, params: &str, is_sgr: bool) -> Self {
        if !is_sgr {
            return self;
        }
        if params.is_empty() {
            return Self::default();
        }
        for param in params.split(';') {
            match param.parse::<u8>().unwrap_or(0) {
                0 => self = Self::default(),
                1 => self.bold = true,
                2 => self.dim = true,
                22 => (self.bold, self.dim) = (false, false),
                39 => self.color = None,
                code => {
                    if let Some(token) = color_token(code) {
                        self.color = token;
                    }
                }
            }
        }
        self
    }

    fn tokens(&self) -> String {
        let mut tokens = Vec::with_capacity(3);
        tokens.extend(self.color);
        if self.bold {
            tokens.push(STRONG);
        }
        if self.dim {
            tokens.push(DIM);
        }
        tokens.join(" ")
    }
}

/// The token for a foreground color code, as `crate::ui` uses the colors:
/// `None` for a code that sets no foreground (a background), `Some(None)`
/// for a foreground with no token of its own.
fn color_token(code: u8) -> Option<Option<&'static str>> {
    Some(match code {
        90 => Some(MUTED),
        31 | 91 => Some("error"),
        32 | 92 => Some("success"),
        33 | 93 => Some("warning"),
        34 | 94 => Some(SYMBOL),
        35 | 95 => Some(MNEMONIC),
        36 => Some(NUMBER),
        96 => Some("info"),
        30 | 37 | 97 => None,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use owo_colors::OwoColorize;

    fn texts(spans: &[Span]) -> Vec<(String, Option<String>)> {
        spans
            .iter()
            .map(|span| (span.t.clone(), span.s.clone()))
            .collect()
    }

    #[test]
    fn styled_text_keeps_its_meaning_as_tokens() {
        let styled = format!(
            "{} {}{} {}",
            "rip".bright_black(),
            "nt!NtClose".bright_blue(),
            "+0x5".bright_black(),
            "BREAK".bold()
        );
        assert_eq!(
            texts(&spans(&styled)),
            [
                ("rip".into(), Some(MUTED.into())),
                (" ".into(), None),
                ("nt!NtClose".into(), Some(SYMBOL.into())),
                ("+0x5".into(), Some(MUTED.into())),
                (" ".into(), None),
                ("BREAK".into(), Some(STRONG.into())),
            ]
        );
    }

    #[test]
    fn a_background_keeps_the_foreground_and_other_sequences_vanish() {
        let styled = format!("{}\x1b[2K{}", "id".cyan().on_black(), "x");
        assert_eq!(
            texts(&spans(&styled)),
            [("id".into(), Some(NUMBER.into())), ("x".into(), None)]
        );
    }

    #[test]
    fn symbol_quiets_the_module_and_offset() {
        assert_eq!(
            texts(&symbol("nt!KiIdleLoop+0x54")),
            [
                ("nt!".into(), Some(MUTED.into())),
                ("KiIdleLoop".into(), Some(SYMBOL.into())),
                ("+0x54".into(), Some(MUTED.into())),
            ]
        );
        assert_eq!(
            texts(&symbol("0xfffff80586ac0f10")),
            [("0xfffff80586ac0f10".into(), Some(MUTED.into()))]
        );
        assert_eq!(
            texts(&symbol("mscorlib.ni+0x5d4de8")),
            [
                ("mscorlib.ni".into(), None),
                ("+0x5d4de8".into(), Some(MUTED.into())),
            ]
        );
    }
}
