use crate::backend::dbg_backend::DebugCapability;
use crate::backend::kd::{KdFileMapping, kd_files, load_map_file};
use crate::base::diagnostics::print_warning;
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::output;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::nt::dump_writer::{DumpWrite, write_kernel_dump};
use crate::nt::userdump::write::{MinidumpWrite, write_minidump as write_minidump_file};
use crate::session::dump::{collect_dump_metadata, collect_process_minidump};
use crate::session::{Motion, Session};
use indicatif::ProgressStyle;
use ntoseye_macros::{command, grammar};
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
    target = Nt,
    state = Halted,
    run = Run,
    capability = TargetControl,
    python = Debugger,
)]
fn reboot(session: &mut Session) -> Result<Motion> {
    session
        .request_reboot()
        .map_err(|error| Error::DebugInfo(format!("failed to reboot target: {error}")))?;
    outln!("target is rebooting; waiting for it to reload");
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
    target = Nt,
    state = Halted,
    run = Run,
    capability = TargetControl,
    python = Debugger,
)]
fn crash(session: &mut Session) -> Result<Motion> {
    session
        .request_crash()
        .map_err(|error| Error::DebugInfo(format!("failed to force target bugcheck: {error}")))?;
    outln!(
        "forcing target bugcheck 0xE2 (MANUALLY_INITIATED_CRASH); the target writes its crash \
         dump before rebooting or breaking in"
    );
    Ok(Motion::Wait)
}

/// Write a full kernel dump of the halted target, or with /u a user-mode
/// minidump of the current process.
///
/// Without /u, .dump writes a full PAGEDU64 kernel dump of a live target;
/// it accepts /f and /ma as WinDbg's full-dump switches. With /u, it writes
/// a user-mode minidump (MDMP) of the current process: the one that .process
/// selected, else the owner of the current thread. The minidump holds the
/// process's threads with the user-mode registers their stacks give, its
/// modules with their CodeView records, its regions as VirtualQuery reports
/// them, and every committed page of its memory that is in physical memory;
/// a page in the page file is not in it. It works on a kernel dump too, and WinDbg and ntoseye --dump
/// open it. .dump writes either file as a stream, and you can cancel it
/// with Ctrl+C.
#[command(
    names = [".dump", "dump"],
    category = "target control",
    kind = Action,
    target = Nt,
    state = Halted,
    capability = MemoryIntrospection,
    writes = [Files],
    forms = [write_kernel_dump_file, write_minidump],
)]
fn write_dump(
    session: &mut Session,
    #[arg(parse = dump_request)] request: DumpRequest,
) -> Result<DumpWritten> {
    if request.minidump {
        write_minidump(session, request.path).map(DumpWritten::Minidump)
    } else {
        write_kernel_dump_file(session, request.path).map(DumpWritten::Kernel)
    }
}

/// Write a full PAGEDU64 kernel dump of the live target (`.dump`).
#[command(form_of = write_dump, live_only, python = Debugger, python_name = "write_dump")]
fn write_kernel_dump_file(session: &mut Session, path: String) -> Result<DumpWrite> {
    if session.target.phys.is_dump() {
        return Err(Error::InvalidArgument(
            "a full kernel dump is written from a live target; .dump /u writes a minidump of \
             the current process"
                .into(),
        ));
    }
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

/// Write a user-mode minidump of the process (`.dump /u`): its threads with
/// their user-mode registers, its modules, its regions, and its memory that
/// is in physical memory.
#[command(form_of = write_dump, python = Process)]
fn write_minidump(session: &mut Session, path: String) -> Result<MinidumpWrite> {
    let process = session.target.selected_process_info()?;
    let model = collect_process_minidump(session, &process)
        .map_err(|error| Error::DebugInfo(format!("cannot prepare the minidump: {error}")))?;
    let pages: u64 = model
        .memory
        .iter()
        .map(|range| (range.end - range.start) / PAGE_SIZE as u64)
        .sum();
    let progress = output::progress_bar(pages, "writing minidump");
    progress.set_style(
        ProgressStyle::with_template("Writing minidump [{bar:40}] {pos}/{len}")?
            .progress_chars("#-"),
    );
    let interrupt = Arc::clone(&session.target.interrupt);
    interrupt.store(false, Ordering::SeqCst);
    let memory = session.target.address_space(process.dtb);
    let result = write_minidump_file(
        Path::new(&path),
        &model,
        |address, page| memory.read_bytes(VirtAddr(address), page).is_ok(),
        || interrupt.swap(false, Ordering::SeqCst),
        || progress.inc(1),
    );
    progress.finish_and_clear();
    let unreadable_pages = result
        .map_err(|error| Error::DebugInfo(format!("failed to write the minidump: {error}")))?;
    Ok(MinidumpWrite {
        path,
        process: process.name,
        pid: process.pid,
        threads: model.threads.len(),
        threads_without_context: model
            .threads
            .iter()
            .filter(|thread| thread.context.is_none())
            .count(),
        modules: model.modules.len(),
        regions: model.regions.len(),
        captured_bytes: pages * PAGE_SIZE as u64,
        demand_zero_bytes: model.zero.iter().map(|range| range.end - range.start).sum(),
        unreadable_pages,
    })
}

/// What `.dump` wrote.
enum DumpWritten {
    Kernel(DumpWrite),
    Minidump(MinidumpWrite),
}

impl Render for DumpWritten {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Kernel(dump) => {
                if dump.unreadable_pages != 0 {
                    outln!("{} pages unreadable (zero-filled)", dump.unreadable_pages);
                }
                outln!("wrote full kernel dump to {}", dump.path);
            }
            Self::Minidump(dump) => {
                if dump.unreadable_pages != 0 {
                    outln!("{} pages unreadable (zero-filled)", dump.unreadable_pages);
                }
                let zeros = if dump.demand_zero_bytes == 0 {
                    String::new()
                } else {
                    format!(
                        " ({} MiB of it never touched, so zeros)",
                        dump.demand_zero_bytes >> 20
                    )
                };
                outln!(
                    "wrote a minidump of {} (PID {}) to {}: {} threads, {} modules, {} regions, \
                     {} MiB of memory{zeros}",
                    dump.process,
                    dump.pid,
                    dump.path,
                    dump.threads,
                    dump.modules,
                    dump.regions,
                    dump.captured_bytes >> 20
                );
                if dump.threads_without_context != 0 {
                    outln!(
                        "{}",
                        ui::muted(&format!(
                            "{} threads have no context: their stacks gave no user-mode registers",
                            dump.threads_without_context
                        ))
                    );
                }
            }
        }
    }
}

/// What `.dump` writes, and where.
pub struct DumpRequest {
    pub path: String,
    /// `/u`: a user-mode minidump of the current process.
    pub minidump: bool,
}

/// `.dump`'s file, among its switches.
#[grammar(usage = "[/f] [/ma] [/u] <file>", complete = None)]
fn dump_request(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<DumpRequest, ArgError> {
    let mut path = None;
    let mut minidump = false;
    while let Some(argument) = cursor.word() {
        if argument.starts_with('/') {
            match argument.to_ascii_lowercase().as_str() {
                "/f" | "/ma" => {}
                "/u" => minidump = true,
                // Unix absolute paths also start with `/`; once the known
                // switches are excluded, treat the first such token as the
                // requested file rather than rejecting `/tmp/out.dmp`.
                _ if path.is_none() => path = Some(argument.into_owned()),
                _ => return Err(ArgError::Missing),
            }
        } else if path.replace(argument.into_owned()).is_some() {
            return Err(ArgError::Missing);
        }
    }
    Ok(DumpRequest {
        path: path.ok_or(ArgError::Missing)?,
        minidump,
    })
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
#[grammar(usage = "[map-file] | -m <target> <host> | -d <target> | -c", complete = None)]
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
            Self::Cleared => outln!("driver replacement map cleared"),
            Self::Removed(target) => outln!("removed mapping for {target}"),
            Self::Added(mapping) => {
                outln!("mapped {} -> {}", mapping.target, mapping.host.display())
            }
            Self::Loaded { count, path } => outln!(
                "loaded {count} mapping{} from {path}",
                if *count == 1 { "" } else { "s" }
            ),
        }
        warn_if_file_io_unsupported(state);
    }
}

fn show_kdfiles(state: &mut ReplState<'_>) {
    let mappings = kd_files().mappings();
    if mappings.is_empty() {
        outln!(
            "{}",
            ui::muted("no driver replacement map; `.kdfiles -m <target> <host>` adds a mapping")
        );
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
        outln!("VM is running");
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
        // The buffer is a bonus here: failing to read it leaves the line above.
        let _ = print_kernel_print_buffer(state, count);
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
            output::neutralize_controls(&line.text)
        );
    }
    Ok(())
}

/// `!dbgprint`'s count of lines, a decimal number; 50 when omitted.
#[grammar(usage = "[count]", complete = [None])]
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
    let bytes = crate::nt::target::dbgprint::chronological(&buffer, position.cursor);
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
            "kernel DbgPrint buffer at {:#x}, {:#x} bytes, {wrapped}",
            position.buffer.0, position.size
        ))
    );
    if lines.is_empty() {
        outln!("{}", ui::muted("the buffer is empty"));
        return Ok(());
    }
    let start = if count == 0 {
        0
    } else {
        lines.len().saturating_sub(count)
    };
    for line in &lines[start..] {
        outln!("{}", output::neutralize_controls(line));
    }
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
