use crate::dbg_backend::DebugCapability;
use crate::diagnostics::print_warning;
use crate::dump_writer::{collect_dump_metadata, write_kernel_dump};
use crate::error::{Error, Result};
use crate::kd::{KdFileMapping, kd_files, load_map_file};
use crate::phys::PhysMem;
use crate::repl::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

repl_command! {
    cmd_reboot();
    names: [".reboot", "reboot", ".restart", "restart"],
    usage: ".reboot",
    summary: "Reboot the debug target and reload its kernel context.",
    details: "The reboot is sent without confirmation. The next KD state-change is handled by the normal target-reload path.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_crash();
    names: [".crash", "crash"],
    usage: ".crash",
    summary: "Force a MANUALLY_INITIATED_CRASH (bugcheck 0xE2).",
    details: "Windows writes its crash dump first (often a minute, during which the target ignores break-ins), then reboots or, with automatic restart disabled, breaks in. Ctrl+C stops waiting.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_dump;
    names: [".dump", "dump"],
    usage: ".dump [/f] [/ma] <file>",
    summary: "Write a full PAGEDU64 kernel dump from the halted target.",
    details: "Both /f and /ma are accepted as WinDbg-compatible full-dump switches. The dump is streamed page by page and can be canceled with Ctrl+C.",
    completion: None,
    run_state: Halted,
}

repl_command! {
    cmd_kdfiles;
    names: [".kdfiles"],
    usage: ".kdfiles [<map-file>] [-m <target> <host>] [-d <target>] [-c]",
    summary: "Serve driver images from host files using a driver replacement map.",
    details: "With no arguments, show mappings and serving statistics. A path loads a WinDbg map file containing three-line records of `map`, target name, and host path. -m adds a mapping, -d removes one, -c clears the map. Target names match case-insensitively on path suffix boundaries; a bare filename matches any directory. Changes take effect on the next driver load.",
    completion: None,
}

repl_command! {
    cmd_status();
    names: ["status"],
    usage: "status",
    summary: "Display current VM status.",
}

repl_command! {
    cmd_capabilities();
    names: ["capabilities"],
    usage: "capabilities",
    summary: "Display backend capabilities.",
}

repl_command! {
    cmd_dbgprint;
    names: ["!dbgprint", "dbgprint"],
    usage: "!dbgprint [count]",
    summary: "Show captured guest debug output (DbgPrint).",
}

fn target_control_available(state: &ReplState<'_>) -> bool {
    let capabilities = state.ctx.capabilities();
    if supports_capability(&capabilities, DebugCapability::TargetControl) {
        true
    } else {
        error!(
            "target control is not supported by the {} backend",
            state.ctx.backend.name()
        );
        false
    }
}

impl ReplState<'_> {
    fn cmd_kdfiles(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        match invocation.argv.first().map(|arg| arg.as_ref()) {
            None => {
                self.show_kdfiles();
                return Ok(());
            }
            Some("-c") => {
                if invocation.argv.len() != 1 {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
                kd_files().clear();
                outln!("Driver replacement map cleared.");
            }
            Some("-d") => {
                let Some(target) = invocation.arg(1).filter(|_| invocation.argv.len() == 2) else {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                };
                if kd_files().remove(target) {
                    outln!("Removed mapping for {target}.");
                } else {
                    error!("no mapping for {target}");
                    return Ok(());
                }
            }
            Some("-m") => {
                let (Some(target), Some(host)) = (invocation.arg(1), invocation.arg(2)) else {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                };
                if invocation.argv.len() != 3 {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
                match kd_files().add(target, Path::new(host)) {
                    Ok(mapping) => {
                        outln!("Mapped {} -> {}.", mapping.target, mapping.host.display())
                    }
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
            Some(path) => match load_map_file(Path::new(path)) {
                Ok(mappings) => {
                    let count = mappings.len();
                    kd_files().set(mappings);
                    outln!(
                        "Loaded {count} mapping{} from {path}.",
                        if count == 1 { "" } else { "s" }
                    );
                }
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
        }
        self.warn_if_file_io_unsupported();
        Ok(())
    }

    fn show_kdfiles(&mut self) {
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
        self.warn_if_file_io_unsupported();
        outln!();
    }

    fn warn_if_file_io_unsupported(&mut self) {
        let capabilities = self.ctx.capabilities();
        if !supports_capability(&capabilities, DebugCapability::TargetFileIo) {
            print_warning(format!(
                "the {} backend cannot serve target file requests; the map will never be consulted",
                self.ctx.backend.name()
            ));
        }
    }

    fn cmd_reboot(&mut self) -> Result<()> {
        if !target_control_available(self) {
            return Ok(());
        }
        if let Err(error) = self.ctx.request_reboot() {
            error!("failed to reboot target: {error}");
            return Ok(());
        }
        outln!("Target is rebooting; waiting for target reload.");
        self.wait_for_stop_after_resume()
    }

    fn cmd_crash(&mut self) -> Result<()> {
        if !target_control_available(self) {
            return Ok(());
        }
        if let Err(error) = self.ctx.request_crash() {
            error!("failed to force target bugcheck: {error}");
            return Ok(());
        }
        outln!(
            "Forcing target bugcheck 0xE2 (MANUALLY_INITIATED_CRASH); the target writes its crash dump before rebooting or breaking in."
        );
        self.wait_for_stop_after_resume()
    }

    fn cmd_dump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(path) = parse_dump_arguments(&invocation) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };

        let capabilities = self.ctx.capabilities();
        if !supports_capability(&capabilities, DebugCapability::MemoryIntrospection) {
            error!(
                "dump writing is not supported by the {} backend",
                self.ctx.backend.name()
            );
            return Ok(());
        }

        if matches!(&*self.ctx.target.phys, PhysMem::Dmp(_)) {
            error!(".dump is not applicable to a static crash dump");
            return Ok(());
        }

        let (metadata, total_pages) = match collect_dump_metadata(self.ctx)
            .and_then(|metadata| metadata.total_pages().map(|pages| (metadata, pages)))
        {
            Ok(prepared) => prepared,
            Err(error) => {
                error!("cannot prepare dump: {error}");
                return Ok(());
            }
        };
        let memory = &*self.ctx.target.phys;
        let progress = ProgressBar::new(total_pages);
        progress.set_style(
            ProgressStyle::with_template("Writing dump [{bar:40}] {pos}/{len}")?
                .progress_chars("#-"),
        );
        let interrupt = Arc::clone(&self.ctx.target.interrupt);
        interrupt.store(false, Ordering::SeqCst);
        let result = write_kernel_dump(
            path,
            memory,
            &metadata,
            || interrupt.swap(false, Ordering::SeqCst),
            || progress.inc(1),
        );
        progress.finish_and_clear();
        match result {
            Ok(unreadable_pages) => {
                if unreadable_pages != 0 {
                    outln!("{unreadable_pages} pages unreadable (zero-filled)");
                }
                outln!("Wrote full kernel dump to {}.", path)
            }
            Err(error) => error!("failed to write dump: {error}"),
        }
        Ok(())
    }

    fn cmd_status(&mut self) -> Result<()> {
        if self.ctx.backend.is_running() {
            outln!("VM is running\n");
        } else {
            if let Err(e) = self
                .ctx
                .backend
                .set_current_thread(&self.ctx.current_thread)
            {
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            print_stop_separator();
            print_break_context(
                &mut *self.ctx.backend,
                &self.ctx.register_map,
                &mut self.ctx.target,
                &self.ctx.breakpoints,
                &self.ctx.current_thread,
            );
        }

        Ok(())
    }

    fn cmd_capabilities(&mut self) -> Result<()> {
        print_backend_capabilities(&self.ctx.capabilities());

        Ok(())
    }

    /// Show captured guest debug output (DbgPrint). The stream also prints live
    /// to the terminal as it arrives; this shows the retained history, last
    /// `count` lines (default 50, or all retained when `count` is 0).
    fn cmd_dbgprint(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_TAIL: usize = 50;
        let count = match invocation.arg(0) {
            Some(arg) => arg
                .parse::<usize>()
                .map_err(|_| Error::DebugInfo(format!("invalid count: {arg}")))?,
            None => DEFAULT_TAIL,
        };

        let page = self.ctx.read_debug_output(0);
        if page.lines.is_empty() {
            outln!("{}\n", ui::muted("no debug output captured"));
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
}

fn parse_dump_arguments<'a>(invocation: &'a CommandInvocation<'a>) -> Option<&'a str> {
    let mut path = None;
    for argument in &invocation.argv {
        let argument = argument.as_ref();
        if argument.starts_with('/') {
            match argument.to_ascii_lowercase().as_str() {
                "/f" | "/ma" => {}
                // Unix absolute paths also start with `/`; once both known
                // switches are excluded, treat the first such token as the
                // requested file rather than rejecting `/tmp/out.dmp`.
                _ if path.is_none() => path = Some(argument),
                _ => return None,
            }
        } else if path.replace(argument).is_some() {
            return None;
        }
    }
    path
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
