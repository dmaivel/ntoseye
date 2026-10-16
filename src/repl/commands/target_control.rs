use crate::dbg_backend::DebugCapability;
use crate::diagnostics::print_warning;
use crate::dump_writer::{collect_dump_metadata, write_kernel_dump};
use crate::error::{Error, Result};
use crate::kd::{KdFileMapping, kd_files, load_map_file};
use crate::output;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::{Motion, Session};
use indicatif::ProgressStyle;
use ntoseye_macros::command;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Reboot the debug target and reload its kernel context.
///
/// ntoseye sends the reboot without confirmation, and handles the next KD
/// state-change through the normal target-reload path.
#[command(
    names = [".reboot", "reboot", ".restart", "restart"],
    category = "target control",
    kind = Run,
    state = Halted,
    run = Run,
    capability = TargetControl,
    python = Debugger,
    usage = ".reboot"
)]
fn reboot(session: &mut Session) -> Result<Motion> {
    session
        .request_reboot()
        .map_err(|error| Error::DebugInfo(format!("failed to reboot target: {error}")))?;
    outln!("Target is rebooting; waiting for target reload.");
    Ok(Motion::Wait)
}

/// Force a MANUALLY_INITIATED_CRASH (bugcheck 0xE2).
///
/// Windows first writes its crash dump, which often takes a minute, and the
/// target ignores break-ins during this time. Then Windows reboots or, if
/// automatic restart is disabled, breaks in. Ctrl+C stops the wait.
#[command(
    names = [".crash", "crash"],
    category = "target control",
    kind = Run,
    state = Halted,
    run = Run,
    capability = TargetControl,
    python = Debugger,
    usage = ".crash"
)]
fn crash(session: &mut Session) -> Result<Motion> {
    session
        .request_crash()
        .map_err(|error| Error::DebugInfo(format!("failed to force target bugcheck: {error}")))?;
    outln!(
        "Forcing target bugcheck 0xE2 (MANUALLY_INITIATED_CRASH); the target writes its crash \
         dump before rebooting or breaking in."
    );
    Ok(Motion::Wait)
}

/// Write a full PAGEDU64 kernel dump from the halted target.
///
/// .dump accepts both /f and /ma as WinDbg-compatible full-dump switches.
/// ntoseye writes the dump as a stream, page by page, and you can cancel it
/// with Ctrl+C.
#[command(
    names = [".dump", "dump"],
    category = "target control",
    kind = Action,
    state = Halted,
    live_only,
    capability = MemoryIntrospection,
    writes = [Files],
    python = none,
    usage = ".dump [/f] [/ma] <file>",
    completion = None
)]
fn write_dump(session: &mut Session, #[arg(parse = dump_path)] path: String) -> Result<DumpWrite> {
    let (metadata, total_pages) = collect_dump_metadata(session)
        .and_then(|metadata| metadata.total_pages().map(|pages| (metadata, pages)))
        .map_err(|error| Error::DebugInfo(format!("cannot prepare dump: {error}")))?;
    let memory = &*session.target.phys;
    let progress = output::progress_bar(total_pages, "writing dump");
    progress.set_style(
        ProgressStyle::with_template("Writing dump [{bar:40}] {pos}/{len}")?.progress_chars("#-"),
    );
    let interrupt = Arc::clone(&session.target.interrupt);
    interrupt.store(false, Ordering::SeqCst);
    let result = write_kernel_dump(
        &path,
        memory,
        &metadata,
        || interrupt.swap(false, Ordering::SeqCst),
        || progress.inc(1),
    );
    progress.finish_and_clear();
    let unreadable_pages =
        result.map_err(|error| Error::DebugInfo(format!("failed to write dump: {error}")))?;
    Ok(DumpWrite {
        path,
        unreadable_pages,
    })
}

/// A kernel dump `.dump` wrote.
pub struct DumpWrite {
    pub path: String,
    /// The pages that could not be read, written as zeros.
    pub unreadable_pages: u64,
}

impl Render for DumpWrite {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.unreadable_pages != 0 {
            outln!("{} pages unreadable (zero-filled)", self.unreadable_pages);
        }
        outln!("Wrote full kernel dump to {}.", self.path)
    }
}

/// `.dump`'s file, among the full-dump switches.
fn dump_path(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    let mut path = None;
    while let Some(argument) = cursor.word() {
        if argument.starts_with('/') {
            match argument.to_ascii_lowercase().as_str() {
                "/f" | "/ma" => {}
                // Unix absolute paths also start with `/`; once both known
                // switches are excluded, treat the first such token as the
                // requested file rather than rejecting `/tmp/out.dmp`.
                _ if path.is_none() => path = Some(argument.into_owned()),
                _ => return Err(ArgError::Missing),
            }
        } else if path.replace(argument.into_owned()).is_some() {
            return Err(ArgError::Missing);
        }
    }
    path.ok_or(ArgError::Missing)
}

/// What `.kdfiles` does to the driver replacement map.
pub enum KdFilesChange {
    Show,
    Clear,
    Remove(String),
    Add { target: String, host: String },
    Load(String),
}

/// What `.kdfiles` changed, for its message.
pub enum KdFilesChanged {
    Shown,
    Cleared,
    Removed(String),
    Added(KdFileMapping),
    Loaded { count: usize, path: String },
}

/// Serve driver images from host files using a driver replacement map.
///
/// Without arguments, .kdfiles shows the mappings and serving statistics. A
/// path loads a WinDbg map file of three-line records: `map`, the target
/// name, and the host path. -m adds a mapping, -d removes one, and -c clears
/// the map. Target names match case-insensitively on path suffix boundaries,
/// and a bare filename matches any directory. Changes apply at the next
/// driver load, so the guest can load a rebuilt driver without you copying
/// it into the guest. See the driver replacement map guide.
#[command(
    names = [".kdfiles"],
    category = "target control",
    kind = Action,
    target = Kernel,
    python = none,
    usage = ".kdfiles [<map-file>] [-m <target> <host>] [-d <target>] [-c]",
    completion = None
)]
fn kdfiles(
    _session: &Session,
    #[arg(parse = kdfiles_change)] change: KdFilesChange,
) -> Result<KdFilesChanged> {
    Ok(match change {
        KdFilesChange::Show => KdFilesChanged::Shown,
        KdFilesChange::Clear => {
            kd_files().clear();
            KdFilesChanged::Cleared
        }
        KdFilesChange::Remove(target) => {
            if !kd_files().remove(&target) {
                return Err(Error::DebugInfo(format!("no mapping for {target}")));
            }
            KdFilesChanged::Removed(target)
        }
        KdFilesChange::Add { target, host } => KdFilesChanged::Added(
            kd_files()
                .add(&target, Path::new(&host))
                .map_err(|error| Error::DebugInfo(error.to_string()))?,
        ),
        KdFilesChange::Load(path) => {
            let mappings = load_map_file(Path::new(&path))
                .map_err(|error| Error::DebugInfo(error.to_string()))?;
            let count = mappings.len();
            kd_files().set(mappings);
            KdFilesChanged::Loaded { count, path }
        }
    })
}

/// `.kdfiles`' words: none, `-c`, `-d <target>`, `-m <target> <host>`, or a
/// map file; any other shape shows the help.
fn kdfiles_change(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<KdFilesChange, ArgError> {
    let words: Vec<String> = cursor.words().map(str::to_string).collect();
    while cursor.word().is_some() {}
    let word = |index: usize| words.get(index).cloned();
    Ok(match (words.first().map(String::as_str), words.len()) {
        (None, _) => KdFilesChange::Show,
        (Some("-c"), 1) => KdFilesChange::Clear,
        (Some("-d"), 2) => KdFilesChange::Remove(word(1).unwrap_or_default()),
        (Some("-m"), 3) => KdFilesChange::Add {
            target: word(1).unwrap_or_default(),
            host: word(2).unwrap_or_default(),
        },
        (Some("-c" | "-d" | "-m"), _) => return Err(ArgError::Missing),
        (Some(path), _) => KdFilesChange::Load(path.to_string()),
    })
}

impl Render for KdFilesChanged {
    fn render(&self, state: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Shown => {
                show_kdfiles(state);
                return;
            }
            Self::Cleared => outln!("Driver replacement map cleared."),
            Self::Removed(target) => outln!("Removed mapping for {target}."),
            Self::Added(mapping) => {
                outln!("Mapped {} -> {}.", mapping.target, mapping.host.display())
            }
            Self::Loaded { count, path } => outln!(
                "Loaded {count} mapping{} from {path}.",
                if *count == 1 { "" } else { "s" }
            ),
        }
        warn_if_file_io_unsupported(state);
    }
}

fn show_kdfiles(state: &mut ReplState<'_>) {
    let mappings = kd_files().mappings();
    if mappings.is_empty() {
        outln!("No driver replacement map. Use `.kdfiles -m <target> <host>`.\n");
        return;
    }
    let width = mappings
        .iter()
        .map(|mapping| mapping.target.chars().count())
        .max()
        .unwrap_or(0);
    for KdFileMapping { target, host } in &mappings {
        outln!("{target:<width$}  ->  {}", host.display());
    }
    let stats = kd_files().stats();
    outln!();
    outln!(
        "served {} open{}, {} byte{} read, {} refused",
        stats.opened,
        if stats.opened == 1 { "" } else { "s" },
        stats.bytes_read,
        if stats.bytes_read == 1 { "" } else { "s" },
        stats.refused
    );
    warn_if_file_io_unsupported(state);
    outln!();
}

fn warn_if_file_io_unsupported(state: &mut ReplState<'_>) {
    let capabilities = state.ctx.capabilities();
    if !supports_capability(&capabilities, DebugCapability::TargetFileIo) {
        print_warning(format!(
            "the {} backend cannot serve target file requests; the map will never be consulted",
            state.ctx.backend.name()
        ));
    }
}

/// Show the current VM status.
#[command(names = ["status"], category = "target control", kind = Query, python = none)]
fn status(state: &mut ReplState<'_>) -> Result<()> {
    if state.ctx.backend.is_running() {
        outln!("VM is running\n");
        return Ok(());
    }
    state
        .ctx
        .backend
        .set_current_thread(&state.ctx.current_thread)
        .map_err(|e| Error::DebugInfo(format!("failed to select execution context: {e}")))?;
    print_stop_separator();
    print_break_context(state.ctx);
    Ok(())
}

/// Show the backend capabilities.
#[command(names = ["capabilities"], category = "target control", kind = Query, python = none)]
fn capabilities(state: &mut ReplState<'_>) -> Result<()> {
    // A user dump's "contexts" are its threads, and what it cannot do
    // is what a snapshot of one process lacks.
    let note = state.ctx.target.user_dump_info().map(|info| {
        format!(
            "user-mode minidump of {}: a static snapshot of one process, whose contexts are its {} captured threads; its memory is read-only, with no physical addresses or page tables, and no kernel",
            info.process_label(),
            info.threads.len()
        )
    });
    print_backend_capabilities(&state.ctx.capabilities(), note.as_deref());
    Ok(())
}

/// Show guest debug output (DbgPrint).
///
/// Shows the last count lines, 50 by default, or all with 0. Over kd and
/// kdnet, it shows what the KD stream delivered since ntoseye attached, and
/// before anything arrived, the kernel's buffer. On the other backends,
/// including a crash dump, it shows the kernel's own DbgPrint buffer
/// (KdPrintCircularBuffer), as WinDbg's !dbgprint does, which also holds
/// what was printed before ntoseye attached. The buffer is 4 KB by default
/// and keeps only the newest output. A print that the debug filter drops
/// (nt!Kd_DEFAULT_Mask, Kd_<component>_Mask) reaches neither.
#[command(
    names = ["!dbgprint", "dbgprint"],
    category = "target control",
    kind = Query,
    target = Kernel,
    python = none,
    usage = "!dbgprint [count]"
)]
fn dbgprint(state: &mut ReplState<'_>, #[arg(parse = dbgprint_count)] count: usize) -> Result<()> {
    if !state.ctx.backend_streams_debug_output() {
        return print_kernel_print_buffer(state, count);
    }
    let page = state.ctx.read_debug_output(0);
    if page.lines.is_empty() {
        // Nothing printed since attach: what the kernel printed before
        // it, such as the drivers that failed at boot, is in its buffer.
        outln!("{}", ui::muted("no debug output since ntoseye attached"));
        if print_kernel_print_buffer(state, count).is_err() {
            outln!();
        }
        return Ok(());
    }
    let start = if count == 0 {
        0
    } else {
        page.lines.len().saturating_sub(count)
    };
    for line in &page.lines[start..] {
        outln!(
            "{} {}",
            ui::muted(&fmt_timestamp(line.timestamp_ms)),
            line.text
        );
    }
    outln!();
    Ok(())
}

/// `!dbgprint`'s count of lines, a decimal number; 50 when omitted.
fn dbgprint_count(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<usize, ArgError> {
    const DEFAULT_TAIL: usize = 50;
    match cursor.word() {
        None => Ok(DEFAULT_TAIL),
        Some(arg) => arg
            .parse::<usize>()
            .map_err(|_| ArgError::Message(format!("invalid count: {arg}"))),
    }
}

/// The last `count` lines of the kernel's DbgPrint buffer (all when 0),
/// oldest first.
fn print_kernel_print_buffer(state: &mut ReplState<'_>, count: usize) -> Result<()> {
    let target = &state.ctx.target;
    let position = target.kernel_print_position()?;
    let buffer = target.kernel_print_buffer(&position)?;
    let bytes = crate::target::dbgprint::chronological(&buffer, position.cursor);
    let text = String::from_utf8_lossy(&bytes).replace('\0', "");
    let lines: Vec<&str> = text
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .collect();
    let wrapped = match position.cursor.rollovers {
        0 => "not wrapped yet".to_string(),
        1 => "wrapped once, so it starts mid-way".to_string(),
        n => format!("wrapped {n} times, so it starts mid-way"),
    };
    outln!(
        "{}",
        ui::muted(&format!(
            "kernel DbgPrint buffer at {:#x}, {} bytes, {wrapped}",
            position.buffer.0, position.size
        ))
    );
    if lines.is_empty() {
        outln!("{}\n", ui::muted("the buffer is empty"));
        return Ok(());
    }
    let start = if count == 0 {
        0
    } else {
        lines.len().saturating_sub(count)
    };
    for line in &lines[start..] {
        outln!("{line}");
    }
    outln!();
    Ok(())
}

/// Render a Unix-millis timestamp as a `HH:MM:SS.mmm` UTC time-of-day prefix.
/// A bare wall-clock prefix is enough to correlate prints; no date needed.
fn fmt_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let tod = secs % 86_400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}
