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

pub mod code;
pub mod frames;
pub mod help;
pub mod lists;
pub mod session;
pub mod stack;
pub mod stop;
pub mod trees;
pub mod types;

use std::io::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tern_sdk::reconcile::Doc;
use tern_sdk::ui::{self, Gap, Span, SpinnerStyle, TextNode, Wrap};
use tern_sdk::wire::{self, Close, Encoder, Frame, Message, Open, Sheet};
use tern_sdk::{Capabilities, Mode, Options, Session, View};

use crate::diagnostics;
use crate::output;

/// What the terminal answered, when it speaks the protocol with flow
/// surfaces.
static CAPABILITIES: OnceLock<Capabilities> = OnceLock::new();
static NEXT_SURFACE: AtomicU64 = AtomicU64::new(1);
/// The surface showing that the target runs, left open so Tern animates it
/// while ntoseye waits for a stop.
static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// The surfaces' role: `data-surface` for the stylesheet's selectors.
const ROLE: &str = "ntoseye";
/// Token colors and the marks the kinds don't draw themselves.
const STYLESHEET: &str = include_str!("ntoseye.css");

/// Ask the terminal whether it draws Tern surfaces. Called once by the
/// interactive prompt before reedline starts reading, since the answer
/// arrives on stdin; anything but Tern (or no tty, a multiplexer,
/// `TERN_TSP=0`) leaves the text renderers on.
pub fn detect() {
    let options = Options::new()
        .app("ntoseye")
        .version(env!("CARGO_PKG_VERSION"))
        .bracketed_paste(false)
        .kitty_keyboard(false);
    let Ok(Some(session)) = Session::<()>::connect(options) else {
        return;
    };
    let capabilities = session.caps().clone();
    // Closing restores the tty and drains the DA1 answer behind the reply,
    // so it never reaches reedline as typed text.
    if session.close().is_ok() && capabilities.has_feature(wire::feature::FLOW) {
        let _ = CAPABILITIES.set(capabilities);
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
    let surface = Surface::new(capabilities);
    let bytes = match Doc::from_view(view()).and_then(|doc| surface.closed(&doc)) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics::print_warning(format!("Tern view failed ({error}); showing text"));
            return text();
        }
    };
    finish_running();
    if output::transcript_open() {
        // Run into a capture only to log: the capture swallows the text.
        let _ = output::capture_output(text);
    }
    write(&bytes);
}

/// Show that the target runs until the next result: a spinner and a timer
/// Tern clocks itself, in place of the line `text` prints.
pub fn running(text: impl FnOnce()) {
    let Some(capabilities) = drawing() else {
        return text();
    };
    finish_running();
    let surface = Surface::new(capabilities);
    let Ok(doc) = Doc::from_view(running_view(None)) else {
        return text();
    };
    let Ok(bytes) = surface.open(&doc) else {
        return text();
    };
    if output::transcript_open() {
        let _ = output::capture_output(text);
    }
    write(&bytes);
    *RUNNING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Running {
        surface,
        doc,
        started: Instant::now(),
    });
}

/// Stop the running indicator at how long the target ran, and leave it in
/// the scrollback. Nothing when none is shown.
pub fn finish_running() {
    let running = RUNNING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some(running) = running else {
        return;
    };
    let ran = running.started.elapsed();
    if let Ok(bytes) = Doc::from_view(running_view(Some(ran)))
        .and_then(|done| running.surface.update(&running.doc, &done))
    {
        write(&bytes);
    }
}

/// The indicator while the target runs, or, given how long it ran, after.
fn running_view(ran: Option<Duration>) -> View {
    let mut row = ui::row().gap(Gap::Sm).role("ntoseye.running");
    row = match ran {
        None => row
            .child(
                ui::spinner()
                    .style(SpinnerStyle::Orbit)
                    .label([span("running", MUTED)]),
            )
            .child(ui::elapsed())
            .child(ui::text([span("Ctrl+C to pause", DIM)])),
        Some(ran) => row
            .child(ui::text([span("ran", MUTED)]))
            .child(ui::elapsed().stopped(u64::try_from(ran.as_millis()).unwrap_or(u64::MAX))),
    };
    View::new().main([row])
}

struct Running {
    surface: Surface,
    doc: Doc,
    started: Instant,
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
        bytes.extend(self.close()?);
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

    /// The second frame, turning `from` into `to`, and the close.
    fn update(&self, from: &Doc, to: &Doc) -> Result<Vec<u8>, tern_sdk::Error> {
        let mut encoder = Encoder::new(self.limit);
        let mut bytes = self.frame(&mut encoder, 2, from, to)?;
        bytes.extend(self.close()?);
        Ok(bytes)
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

    fn close(&self) -> Result<Vec<u8>, tern_sdk::Error> {
        Encoder::new(self.limit).encode(&Message::Close(Close {
            id: self.id.clone(),
            keep: true,
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
