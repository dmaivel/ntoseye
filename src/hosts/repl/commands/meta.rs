use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;

use crate::base::bytes::utf16le_nul_terminated;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::output;
use crate::base::time::filetime_to_iso;
use crate::base::types::{CodeMachine, VirtAddr};
#[cfg(feature = "python")]
use crate::hosts::python::embed;
use crate::nt::expr::{Expr, NumberRadix};
use crate::nt::target::meta::{
    ErrorCode, ErrorCodeKind, TargetDump, TargetTime, TargetUserDump, TargetVersion, UserDumpTime,
    decode_error_code, decode_error_code_as_ntstatus,
};
use crate::nt::target::{Target, TargetKind};

use ntoseye_macros::{command, grammar};

use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::session::Session;

const PRINTF_C_STRING_LIMIT: usize = 4096;
const PRINTF_WIDE_STRING_LIMIT: usize = 2048;

/// One group of the `.help` listing: a category's commands, the Python
/// commands, or the user aliases.
pub struct HelpGroup {
    pub title: String,
    pub entries: Vec<HelpEntry>,
}

/// One line of a [`HelpGroup`]: a name and what it does (a command's
/// summary, a Python command's first help line, an alias's expansion).
pub struct HelpEntry {
    pub name: String,
    pub summary: String,
    /// The command's other names, comma-separated; empty when it has none.
    pub aliases: String,
}

fn print_help_listing(groups: &[HelpGroup]) {
    for group in groups {
        outln!("{}", ui::label(&group.title));
        for entry in &group.entries {
            if entry.aliases.is_empty() {
                outln!("  {:<24} {}", entry.name, entry.summary);
            } else {
                outln!(
                    "  {:<24} {} (aliases: {})",
                    entry.name,
                    entry.summary,
                    entry.aliases
                );
            }
        }
        outln!();
    }
}

/// Reload custom commands and aliases.
#[command(names = ["reload-scripts"], category = "session", kind = Host, python = none)]
fn reload_scripts(state: &mut ReplState<'_>) -> Result<()> {
    #[cfg(feature = "python")]
    {
        let py_report = embed::load_commands_dir();
        embed::print_script_load_report(&py_report);
        *state.caches.user_commands.write().unwrap() = initial_user_commands();
    }
    #[cfg(not(feature = "python"))]
    print_python_commands_notice();
    let alias_report = state.reload_aliases();
    print_alias_load_report(&alias_report);
    Ok(())
}

/// Show or set the default numeric radix for REPL expressions.
#[command(
    names = ["n"],
    category = "symbols, types, and expressions",
    kind = Host,
    python = none,
)]
fn radix(state: &mut ReplState<'_>, #[arg(name = "8|10|16")] radix: Option<String>) -> Result<()> {
    if let Some(value) = radix {
        state.radix = match value.as_str() {
            "8" => NumberRadix::Octal,
            "10" => NumberRadix::Decimal,
            "16" => NumberRadix::Hexadecimal,
            _ => {
                return Err(Error::DebugInfo(format!(
                    "invalid radix '{value}' (use 8, 10, or 16)"
                )));
            }
        };
    }

    let name = match state.radix {
        NumberRadix::Octal => "octal",
        NumberRadix::Decimal => "decimal",
        NumberRadix::Hexadecimal => "hexadecimal",
    };
    outln!("radix {} ({name})", state.radix.value());
    Ok(())
}

/// Show or set the effective code machine.
///
/// With no argument, shows the selected machine. x86, amd64, and arm64 (on an
/// ARM64 target only) make u, ub, uf, and editor disassembly decode all code as
/// that instruction set, and auto or . goes back to selection by context and
/// image. This selection covers the x86 images of a WOW64 program and, on
/// ARM64, also an emulated x64 image and the x64 ranges of an ARM64X/ARM64EC
/// hybrid. x86 also makes ds/dS read 32-bit (WOW64) string descriptors.
#[command(
    names = [".effmach"],
    category = "processes and modules",
    kind = Action,
    python = none,
)]
fn effmach(
    session: &mut Session,
    #[arg(name = "x86|amd64|arm64|auto|.")] machine: Option<String>,
) -> Result<()> {
    if let Some(machine) = machine {
        let machine = machine.to_ascii_lowercase();
        let effective = match machine.as_str() {
            "x86" => Some(CodeMachine::X86),
            "amd64" => Some(CodeMachine::Amd64),
            "arm64" => Some(CodeMachine::Arm64),
            "." | "auto" => None,
            _ => {
                return Err(Error::DebugInfo(format!(
                    "invalid effective machine '{machine}' (use x86, amd64, arm64, or auto)"
                )));
            }
        };
        let arch = session.target.arch();
        if let Some(effective) = effective
            && !arch.runs_code(effective)
        {
            return Err(Error::DebugInfo(format!(
                "an {} target runs no {} code; use one it runs, or auto",
                arch.label(),
                effective.label()
            )));
        }
        session.target.effmach = effective;
    }

    match session.target.effmach {
        Some(machine) => outln!("effective machine  {}", machine.label()),
        // Auto picks a machine per address, so the target's own is the one
        // in effect for its native code.
        None => {
            let native = session.target.arch().code_machine();
            outln!(
                "effective machine  auto ({} target; by context and image)",
                native.label()
            );
        }
    }
    Ok(())
}

/// Print text without evaluating expressions in it.
#[command(
    names = [".echo", "echo"],
    category = "session",
    kind = Host,
    python = none,
    style = ExpressionTail
)]
fn echo(_state: &mut ReplState<'_>, #[arg(raw, usage = "[text]")] text: String) -> Result<()> {
    let mut text = text.as_str();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        text = &text[1..text.len() - 1];
    }
    outln!("{text}");
    Ok(())
}

/// Print the current date and time of the host in UTC.
#[command(names = [".echotime"], category = "session", kind = Host, python = none)]
fn echotime(_state: &mut ReplState<'_>) -> Result<()> {
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_nanos() / 100).ok())
        .and_then(|ticks| filetime_to_iso(ticks.checked_add(FILETIME_UNIX_EPOCH)?))
        .ok_or_else(|| {
            Error::DebugInfo("the host clock is outside the representable range".to_string())
        })?;
    outln!("Debugger (not debuggee) time: {now}");
    Ok(())
}

/// Format debugger values with WinDbg-style printf specifiers.
///
/// Put the arguments after the format and separate them with commas, as in
/// WinDbg (`.printf "%p %d\n", poi(@rcx + 8), @$t0`). If each argument is one
/// word, you can separate them with spaces.
#[command(
    names = [".printf"],
    category = "session",
    kind = Host,
    python = none,
    style = ExpressionTail
)]
fn printf(
    state: &mut ReplState<'_>,
    #[arg(raw, usage = "\"<format>\" [, <argument>]...", complete = Expression)] tail: String,
    #[arg(invoked)] name: &str,
) -> Result<()> {
    let Some((format, args)) = parse_printf_tail(&tail) else {
        outln!("{}", command_help(name));
        return Ok(());
    };
    // An unreadable argument is reported (the REPL prints the error), not
    // propagated: `.printf` is the body of a log point, and a single bad read
    // must not tear down the session that is running it.
    let text = format_printf(&format, &args, &state.ctx.target, state.radix)?;
    // WinDbg's `.printf` emits exactly the format's characters, which is
    // why its examples end in `\n`; appending one here would double it.
    out!("{text}");
    Ok(())
}

/// Clear the terminal screen if stdout is a terminal.
#[command(names = [".cls"], category = "session", kind = Host, python = none)]
fn cls(_state: &mut ReplState<'_>) -> Result<()> {
    if std::io::stdout().is_terminal() {
        out!("\x1b[2J\x1b[H");
    }
    Ok(())
}

/// Start a debugger transcript and replace any existing file.
#[command(
    names = [".logopen"],
    category = "session",
    kind = Host,
    python = none,
)]
fn logopen(_state: &mut ReplState<'_>, file: String) -> Result<()> {
    open_log_file(&file, false)
}

/// Start a debugger transcript and append it to the file.
#[command(
    names = [".logappend"],
    category = "session",
    kind = Host,
    python = none,
)]
fn logappend(_state: &mut ReplState<'_>, file: String) -> Result<()> {
    open_log_file(&file, true)
}

fn open_log_file(path: &str, append: bool) -> Result<()> {
    output::open_log(path, append)
        .map_err(|error| Error::DebugInfo(format!("failed to open log '{path}': {error}")))?;
    outln!(
        "log {} {}",
        if append { "appending to" } else { "opened" },
        path
    );
    Ok(())
}

/// Close the debugger transcript.
#[command(names = [".logclose"], category = "session", kind = Host, python = none)]
fn logclose(_state: &mut ReplState<'_>) -> Result<()> {
    if output::close_log() {
        outln!("log closed");
    } else {
        outln!("no log is open");
    }
    Ok(())
}

/// List commands or show detailed help for one command.
#[command(
    names = [".hh", "help", ".help"],
    category = "session",
    kind = Host,
    python = none,
)]
fn help(state: &mut ReplState<'_>, command: Option<String>) -> Result<()> {
    if let Some(name) = command.as_deref() {
        if let Some((_, help, _)) = state
            .caches
            .user_commands
            .read()
            .unwrap()
            .iter()
            .find(|(command, _, _)| command == name)
        {
            outln!("{name}\n{help}");
            return Ok(());
        }
        if let Some((_, expansion)) = state
            .aliases
            .entries()
            .into_iter()
            .find(|(alias, _)| alias == name)
        {
            outln!("alias {name} {expansion}");
            return Ok(());
        }
        match command_registry().get(name) {
            None => error!("unknown command '{name}'"),
            Some(spec) => {
                outln!("{}", spec_help(spec));
            }
        }
        return Ok(());
    }

    let mut groups: BTreeMap<&'static str, BTreeMap<&'static str, &'static CommandSpec>> =
        BTreeMap::new();
    // A user-mode minidump refuses every kernel command, so the listing
    // leaves them out; `help <command>` still describes each.
    let user_dump = state.ctx.target.kind() == TargetKind::UserDump;
    let mut hidden = BTreeSet::new();
    for (_, spec) in command_registry().command_names() {
        let canonical = spec.names[0];
        if user_dump && spec.effects.target.needs_kernel() {
            hidden.insert(canonical);
            continue;
        }
        groups
            .entry(spec.category)
            .or_default()
            .insert(canonical, spec);
    }
    let mut listing: Vec<HelpGroup> = groups
        .into_iter()
        .map(|(category, specs)| HelpGroup {
            title: category.to_string(),
            entries: specs
                .into_values()
                .map(|spec| HelpEntry {
                    name: spec.names[0].to_string(),
                    summary: spec.summary.to_string(),
                    aliases: spec.names[1..].join(", "),
                })
                .collect(),
        })
        .collect();

    let user_commands = state.caches.user_commands.read().unwrap().clone();
    if !user_commands.is_empty() {
        listing.push(HelpGroup {
            title: "python commands".to_string(),
            entries: user_commands
                .into_iter()
                .map(|(name, help, _)| HelpEntry {
                    summary: help.lines().next().unwrap_or("").to_string(),
                    name,
                    aliases: String::new(),
                })
                .collect(),
        });
    }
    let aliases = state.aliases.entries();
    if !aliases.is_empty() {
        listing.push(HelpGroup {
            title: "user aliases".to_string(),
            entries: aliases
                .into_iter()
                .map(|(name, expansion)| HelpEntry {
                    name,
                    summary: expansion,
                    aliases: String::new(),
                })
                .collect(),
        });
    }
    print_help_listing(&listing);
    if !hidden.is_empty() {
        outln!(
            "{}",
            ui::muted(&format!(
                "{} commands that need a kernel target are not listed: this is a user-mode minidump",
                hidden.len()
            ))
        );
    }
    Ok(())
}

/// Exit, remove the breakpoints of this session, and leave the guest running.
///
/// This is the WinDbg qd command (quit and detach), and ntoseye also accepts
/// qd. If this session halted the guest, q resumes it. If q cannot remove a
/// breakpoint from the guest, it leaves the guest halted, because if q resumed
/// that guest, the breakpoint could trap when there is no debugger.
#[command(
    names = ["q", "quit", "qd"],
    category = "session",
    kind = Host,
    python = none,
    flow = Quit
)]
fn quit(_state: &mut ReplState<'_>) -> Result<()> {
    // The host quits on the command's flow: it removes the breakpoints and
    // resumes the guest it halted.
    Ok(())
}

/// Show version information for the target, kernel, symbols, processor, and
/// debugger.
#[command(
    names = ["vertarget", "version"],
    category = "target control",
    kind = Query,
    target = Nt,
    python = Inspect,
    python_name = "version"
)]
fn target_version(session: &mut Session) -> Result<TargetVersion> {
    session.target_version()
}

impl Render for TargetVersion {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_target_version(self);
    }
}

/// Show the target UTC time and the system uptime.
#[command(
    names = [".time"],
    category = "target control",
    kind = Query,
    target = Nt,
    python = Inspect,
    python_name = "time"
)]
fn target_time(session: &Session) -> Result<TargetTime> {
    session.target.target_time()
}

impl Render for TargetTime {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_target_time(self);
    }
}

/// Decode an NTSTATUS, Win32, or HRESULT error code.
#[command(
    names = ["!error", "!ntstatus"],
    category = "analysis",
    kind = Query,
    python = none,
)]
fn error_code(
    _session: &Session,
    #[arg(parse = error_code_arg)] code: u64,
    #[arg(invoked)] name: &str,
) -> Result<ErrorCode> {
    Ok(if name == "!ntstatus" {
        decode_error_code_as_ntstatus(code)
    } else {
        decode_error_code(code)
    })
}

/// `!error`'s code: an expression in the current radix, of 32 bits.
#[grammar(usage = "<{}>", complete = Expression)]
fn error_code_arg(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    let text = cursor.word().ok_or(ArgError::Missing)?;
    let code = cx
        .eval(&text)
        .map_err(|error| match error {
            ArgError::Message(error) => {
                ArgError::Message(format!("invalid error code '{text}': {error}"))
            }
            ArgError::Missing => ArgError::Missing,
        })?
        .0;
    if u32::try_from(code).is_err() {
        return Err(ArgError::Message(format!(
            "error code '{text}' exceeds 32 bits"
        )));
    }
    Ok(code)
}

impl Render for ErrorCode {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_error_code(self);
    }
}

impl ReplState<'_> {
    pub fn cmd_user(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        #[cfg(feature = "python")]
        if embed::has_command(invocation.name) {
            let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
            if let Err(error) = embed::dispatch(invocation.name, &args, self.ctx) {
                error!("{}: {}", invocation.name, error);
            }
            return Ok(());
        }

        let hint = match invocation.name {
            "??" => {
                ": `dx` shows a typed expression and its fields \
                 (`dx ((nt!_EPROCESS*)@rcx)->UniqueProcessId`), and `?` evaluates an \
                 expression"
            }
            _ if self.context == DispatchContext::Interactive => {
                " (try pressing tab to see available commands)"
            }
            _ => " (`help` lists the commands)",
        };
        error!("unknown command '{}'{hint}", invocation.name);

        Ok(())
    }
}

/// Every built-in command's help as JSON, for the documentation site's
/// generated reference: `[{"category", "names", "usage", "summary",
/// "details"}]` (`details` may be null), grouped as `.hh` groups them and
/// sorted by category, then canonical name.
pub fn command_reference_json() -> String {
    let mut specs: Vec<&CommandSpec> = COMMANDS.iter().collect();
    specs.sort_by_key(|spec| (spec.category, spec.names[0]));
    let entries: Vec<String> = specs
        .into_iter()
        .map(|spec| {
            let names: Vec<String> = spec.names.iter().map(|name| json_string(name)).collect();
            format!(
                "{{\"category\":{},\"names\":[{}],\"usage\":{},\"summary\":{},\"details\":{}}}",
                json_string(spec.category),
                names.join(","),
                json_string(spec.usage),
                json_string(spec.summary),
                spec.details.map_or_else(|| "null".to_string(), json_string)
            )
        })
        .collect();
    format!("[{}]", entries.join(",\n"))
}

/// `value` as a JSON string literal, quotes included.
pub fn json_string(value: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn print_target_version(detail: &TargetVersion) {
    // One label column per block: the user-mode block's longest label is
    // `service pack`, the kernel block's `product version`.
    let width = if detail.user_dump.is_some() { 12 } else { 15 };
    outln!("{}", ui::label("target version"));
    outln!(
        "  {}  Windows {}.{} build {}{}",
        field(width, "target"),
        detail
            .major_version
            .map_or_else(|| "?".to_string(), |value| value.to_string()),
        detail
            .minor_version
            .map_or_else(|| "?".to_string(), |value| value.to_string()),
        detail
            .build_number
            .map_or_else(|| "?".to_string(), |value| value.to_string()),
        detail
            .build_lab
            .as_ref()
            .map(|lab| format!(" ({lab})"))
            .unwrap_or_default()
    );
    outln!("  {}  {}", field(width, "arch"), detail.architecture);
    if let Some(user_dump) = &detail.user_dump {
        print_user_dump_version(detail, user_dump);
        return;
    }
    if let Some(kernel) = &detail.kernel {
        match kernel.size {
            Some(size) => outln!(
                "  {}  {} size {:#x}",
                field(width, "kernel"),
                ui::addr(kernel.base.0),
                size
            ),
            None => outln!(
                "  {}  {} size -",
                field(width, "kernel"),
                ui::addr(kernel.base.0)
            ),
        }
    } else {
        outln!("  {}  -", field(width, "kernel"));
    }
    let pdb_guid = detail
        .kernel
        .as_ref()
        .and_then(|kernel| kernel.pdb_guid.as_deref());
    let pdb_age = detail.kernel.as_ref().and_then(|kernel| kernel.pdb_age);
    if let (Some(guid), Some(age)) = (pdb_guid, pdb_age) {
        outln!(
            "  {}  ntoskrnl.pdb GUID {} age {}",
            field(width, "pdb"),
            guid,
            age
        );
    } else {
        outln!("  {}  -", field(width, "pdb"));
    }
    if let Some(kernel) = &detail.kernel {
        if let Some(version) = &kernel.file_version {
            outln!("  {}  {}", field(width, "file version"), version);
        }
        if let Some(version) = &kernel.product_version {
            outln!("  {}  {}", field(width, "product version"), version);
        }
    }
    outln!(
        "  {}  {}",
        field(width, "processors"),
        detail
            .processors
            .map_or_else(|| "-".to_string(), |value| value.to_string())
    );
    outln!("  {}  {}", field(width, "product"), detail.product);
    outln!(
        "  {}  {}",
        field(width, "uptime"),
        detail.time.uptime.as_deref().unwrap_or("-")
    );
    outln!(
        "  {}  {}",
        field(width, "backend"),
        detail.backend.as_deref().unwrap_or("-")
    );
    outln!("  {}  {}", field(width, "ntoseye"), detail.debugger_version);
    outln!("  {}  {}", field(width, "symbol path"), detail.symbol_path);
    outln!(
        "  {}  {}",
        field(width, "symbol status"),
        detail.symbol_status.as_deref().unwrap_or("-")
    );
    if let Some(time) = detail.time.system_time_iso.as_deref() {
        outln!("  {}  {}", field(width, "system time"), time);
    }
    if let Some(dump) = &detail.dump {
        print_dump_header(dump);
    }
}

/// The crash dump header's own fields, as a sub-block of `vertarget`. The
/// header's time and uptime are left out: the block above shows the
/// target's.
fn print_dump_header(dump: &TargetDump) {
    const WIDTH: usize = 18;
    let yes_no = |value: bool| if value { "yes" } else { "no" };
    outln!("  {}", ui::muted("dump header"));
    outln!("    {}  {}", field(WIDTH, "triage"), yes_no(dump.is_triage));
    outln!(
        "    {}  {:#x}",
        field(WIDTH, "bugcheck"),
        dump.bugcheck_code
    );
    let parameters = dump
        .bugcheck_parameters
        .iter()
        .map(|value| format!("{value:#x}"))
        .collect::<Vec<_>>()
        .join(" ");
    outln!(
        "    {}  {}",
        field(WIDTH, "parameters"),
        if parameters.is_empty() {
            "-"
        } else {
            parameters.as_str()
        }
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "build type"),
        named_value(
            dump.major_version,
            match dump.major_version {
                0xf => Some("free"),
                0xc => Some("checked"),
                _ => None,
            }
        )
    );
    outln!("    {}  {}", field(WIDTH, "build"), dump.minor_version);
    outln!(
        "    {}  {:#x}",
        field(WIDTH, "product type"),
        dump.product_type
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "processors"),
        dump.number_processors
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "machine"),
        named_value(
            dump.machine_image_type,
            match dump.machine_image_type {
                0x8664 => Some("AMD64"),
                0xaa64 => Some("ARM64"),
                0x14c => Some("x86"),
                _ => None,
            }
        )
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "service pack build"),
        dump.service_pack_build
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "DTB"),
        ui::addr(dump.directory_table_base.0)
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "kernel base"),
        dump.kernel_base
            .map_or_else(|| "-".to_string(), |base| ui::addr(base.0))
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "exception"),
        dump.exception_code
            .map_or_else(|| "-".to_string(), |code| format!("{code:#010x}"))
    );
    outln!(
        "    {}  {}",
        field(WIDTH, "triage overflowed"),
        yes_no(dump.triage_overflowed)
    );
}

/// An enum value as `Name (0xN)`, or `0xN` when it has no known name.
fn named_value(value: u32, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("{name} ({value:#x})"),
        None => format!("{value:#x}"),
    }
}

fn print_target_time(detail: &TargetTime) {
    outln!("{}", ui::label("target time"));
    if let Some(user_dump) = &detail.user_dump {
        print_user_dump_time(user_dump);
        return;
    }
    match (detail.system_time, detail.system_time_iso.as_deref()) {
        (Some(raw), Some(iso)) => outln!("  {}  {} ({raw:#x})", field(11, "system time"), iso),
        (Some(raw), None) => outln!("  {}  - ({raw:#x})", field(11, "system time")),
        _ => outln!("  {}  -", field(11, "system time")),
    }
    match (detail.uptime_seconds, detail.uptime.as_deref()) {
        (Some(seconds), Some(formatted)) => outln!(
            "  {}  {} ({seconds} seconds)",
            field(11, "uptime"),
            formatted
        ),
        _ => outln!("  {}  -", field(11, "uptime")),
    }
}

/// `vertarget` past the version line on a user-mode minidump: what its
/// SystemInfo, MiscInfo, and header record. It has no kernel to describe.
fn print_user_dump_version(detail: &TargetVersion, user_dump: &TargetUserDump) {
    let processor = if detail.architecture == "AMD64" {
        format!(
            "family {}, model {:#x}, stepping {:#x}",
            user_dump.processor_level,
            user_dump.processor_revision >> 8,
            user_dump.processor_revision & 0xff
        )
    } else {
        format!(
            "level {}, revision {:#x}",
            user_dump.processor_level, user_dump.processor_revision
        )
    };
    outln!(
        "  {}  {} ({processor})",
        field(12, "processors"),
        detail
            .processors
            .map_or_else(|| "-".to_string(), |value| value.to_string())
    );
    outln!("  {}  {}", field(12, "product"), detail.product);
    if let Some(service_pack) = &user_dump.service_pack {
        outln!("  {}  {}", field(12, "service pack"), service_pack);
    }
    let process = user_dump.process_name.as_deref().unwrap_or("-");
    match user_dump.process_id {
        Some(pid) => outln!("  {}  {process} (PID {pid})", field(12, "process")),
        None => outln!("  {}  {process}", field(12, "process")),
    }
    outln!(
        "  {}  user-mode minidump, {} threads, {} modules",
        field(12, "dump"),
        user_dump.threads,
        user_dump.modules
    );
    outln!(
        "  {}  {:#x} ({})",
        field(12, "dump type"),
        user_dump.flags,
        user_dump.flag_names.join(" | ")
    );
    if let Some(time) = &detail.time.user_dump {
        outln!(
            "  {}  {}",
            field(12, "dump written"),
            time.written_iso.as_deref().unwrap_or("-")
        );
    }
    outln!(
        "  {}  {}",
        field(12, "exception"),
        user_dump
            .exception_code
            .map_or_else(|| "-".to_string(), |code| format!("{code:#010x}"))
    );
    outln!(
        "  {}  {}",
        field(12, "backend"),
        detail.backend.as_deref().unwrap_or("-")
    );
    outln!("  {}  {}", field(12, "ntoseye"), detail.debugger_version);
    outln!("  {}  {}", field(12, "symbol path"), detail.symbol_path);
}

/// `.time` on a user-mode minidump: when it was written and how long its
/// process had run. It records no system clock or system uptime.
fn print_user_dump_time(detail: &UserDumpTime) {
    let written = detail.written_iso.as_deref().unwrap_or("out of range");
    outln!(
        "  {}  {written} ({:#x})",
        field(16, "dump written"),
        detail.written
    );
    if let Some(local) = &detail.written_local {
        outln!(
            "  {}  {local}{}",
            field(16, "local time"),
            detail
                .time_zone
                .as_deref()
                .filter(|zone| !zone.is_empty())
                .map(|zone| format!(" ({zone})"))
                .unwrap_or_default()
        );
    }
    match detail.process_created_iso.as_deref() {
        Some(created) => outln!("  {}  {created}", field(16, "process created")),
        None => outln!("  {}  -", field(16, "process created")),
    }
    if let (Some(seconds), Some(uptime)) = (detail.process_uptime_seconds, &detail.process_uptime) {
        outln!(
            "  {}  {uptime} ({seconds} seconds)",
            field(16, "process uptime")
        );
    }
    match (detail.user_time_seconds, detail.kernel_time_seconds) {
        (Some(user), Some(kernel)) => outln!(
            "  {}  user {user} s, kernel {kernel} s",
            field(16, "process CPU time")
        ),
        _ => outln!("  {}  -", field(16, "process CPU time")),
    }
    outln!(
        "  {}  not recorded in a user-mode minidump",
        field(16, "system time")
    );
}

/// A field label of `vertarget` or `.time`, padded to its block's label
/// column before it is muted, so that the escape codes do not count.
fn field(width: usize, label: &str) -> String {
    ui::muted(&format!("{label:<width$}"))
}

fn parse_printf_tail(text: &str) -> Option<(String, Vec<String>)> {
    // WinDbg's own form, `"format", arg, ...`: each argument is an
    // expression up to the next comma outside parentheses, spaces and all.
    if let Some((format, rest)) = take_quoted(text.trim())
        && let Some(rest) = rest.trim_start().strip_prefix(',')
    {
        let args = split_top_level(rest, ',')?;
        return (!args.contains(&""))
            .then(|| (format, args.into_iter().map(String::from).collect()));
    }
    let line = format!(".printf {text}");
    let parsed = parse_command(&line).ok()??;
    let invocation = parsed.invocation(CommandStyle::StructuredArgs).ok()?;
    let format = invocation.arg(0)?.to_string();
    let args = invocation
        .argv
        .into_iter()
        .skip(1)
        .map(|argument| argument.into_owned())
        .collect();
    Some((format, args))
}

fn read_wide_string(target: &Target, address: VirtAddr, max_chars: usize) -> Option<String> {
    let count = max_chars.checked_mul(2)?;
    let mut bytes = vec![0u8; count];
    target
        .context_memory()
        .read_bytes(address, &mut bytes)
        .ok()?;
    Some(utf16le_nul_terminated(&bytes))
}

fn format_printf(
    format: &str,
    args: &[String],
    target: &Target,
    radix: NumberRadix,
) -> Result<String> {
    let chars: Vec<char> = format.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    let mut arg_index = 0;
    while index < chars.len() {
        // WinDbg's `.printf` takes the standard C control characters, so a
        // format ending in `\n` must break the line rather than print an `n`.
        if chars[index] == '\\' && index + 1 < chars.len() {
            let (escaped, width) = match chars[index + 1] {
                'n' => ('\n', 2),
                't' => ('\t', 2),
                'r' => ('\r', 2),
                'b' => ('\u{8}', 2),
                '0' => ('\0', 2),
                '\\' => ('\\', 2),
                '"' => ('"', 2),
                // An unknown escape keeps both characters, so a Windows path
                // in a format string survives.
                _ => ('\\', 1),
            };
            output.push(escaped);
            index += width;
            continue;
        }
        if chars[index] != '%' || index + 1 >= chars.len() {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        let spec = chars[index];
        if spec == '%' {
            output.push('%');
            index += 1;
            continue;
        }
        let extended = matches!(spec, 'm' | 's')
            && index + 1 < chars.len()
            && matches!(chars[index + 1], 'a' | 'u');
        if extended {
            index += 1;
        }
        let Some(argument) = args.get(arg_index) else {
            output.extend(chars[start..index + 1].iter());
            index += 1;
            continue;
        };
        let value = || Expr::eval_with_radix(argument, target, radix).map(|value| value.0);
        let rendered = match (spec, extended.then_some(chars[index])) {
            ('d', None) => (value()? as i64).to_string(),
            ('u', None) => value()?.to_string(),
            ('x', None) => format!("{:x}", value()?),
            ('p', None) => ui::addr(value()?),
            ('c', None) => char::from_u32(value()? as u32)
                .unwrap_or('\u{fffd}')
                .to_string(),
            ('s', None) => argument.to_string(),
            ('m', Some('a')) => {
                let address = value()?;
                target
                    .read_c_string(VirtAddr(address), PRINTF_C_STRING_LIMIT)
                    .unwrap_or_else(|_| format!("<unreadable {address:#x}>"))
            }
            ('m', Some('u')) => {
                let address = value()?;
                read_wide_string(target, VirtAddr(address), PRINTF_WIDE_STRING_LIMIT)
                    .unwrap_or_else(|| format!("<unreadable {address:#x}>"))
            }
            ('y', None) => {
                let address = value()?;
                target
                    .closest_symbol_current_context(VirtAddr(address))
                    .unwrap_or_else(|| format!("{address:#x}"))
            }
            _ => {
                output.extend(chars[start..=index].iter());
                index += 1;
                continue;
            }
        };
        output.push_str(&rendered);
        arg_index += 1;
        index += 1;
    }
    Ok(output)
}

fn print_error_code(detail: &ErrorCode) {
    const WIDTH: usize = 11;
    let name = if detail.name.is_empty() {
        "-"
    } else {
        detail.name.as_str()
    };
    match detail.kind {
        ErrorCodeKind::Ntstatus | ErrorCodeKind::Hresult => {
            let kind = if detail.kind == ErrorCodeKind::Ntstatus {
                "NTSTATUS"
            } else {
                "HRESULT"
            };
            outln!("{kind} {:#010x}", detail.code);
            outln!("  {}  {name}", field(WIDTH, "name"));
            if let Some(severity) = detail.severity {
                outln!("  {}  {severity}", field(WIDTH, "severity"));
            }
            if let Some(facility) = detail.facility {
                outln!("  {}  {facility:#x}", field(WIDTH, "facility"));
            }
            if let Some(customer) = detail.customer {
                outln!(
                    "  {}  {}",
                    field(WIDTH, "customer"),
                    if customer { "yes" } else { "no" }
                );
            }
            if let Some(win32) = detail.win32_code {
                outln!(
                    "  {}  {} ({win32:#x})",
                    field(WIDTH, "Win32 error"),
                    detail.win32_name.as_deref().unwrap_or("-")
                );
            }
        }
        ErrorCodeKind::Win32 => {
            outln!("Win32 error {:#x}", detail.code);
            outln!("  {}  {name}", field(WIDTH, "name"));
        }
        ErrorCodeKind::Unknown => outln!(
            "unknown error code {:#x}: {}",
            detail.code,
            detail.description
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::error::Error;
    use crate::base::output::capture;
    use crate::hosts::repl::ReplState;
    use crate::session::session_over_memory;

    #[test]
    fn printf_reports_expression_errors_instead_of_printing_placeholders() {
        let session = session_over_memory(0x1000, &[0; 8]);
        let result = format_printf(
            "major[%p] wired",
            &["missing_local".into()],
            &session.target,
            NumberRadix::Hexadecimal,
        );
        assert!(matches!(result, Err(Error::SymbolNotFound(name)) if name == "missing_local"));
    }

    #[test]
    fn printf_interprets_control_characters_and_adds_nothing() {
        // Driven through `dispatch_line`, because the command parser also
        // handles backslashes: a test that called `format_printf` directly
        // passed while the REPL still printed a literal `n`.
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        let (result, text) =
            capture(|| state.dispatch_line("\u{2e}printf \"a\\tb\\nc=%u\\n\" 0n42"));
        result.unwrap();
        assert_eq!(text, "a\tb\nc=42\n");

        // An unrecognized escape keeps both characters, so a Windows path in
        // a format string survives.
        let (result, text) = capture(|| state.dispatch_line("\u{2e}printf \"C:\\dir\\x\""));
        result.unwrap();
        assert_eq!(text, "C:\\dir\\x");
    }

    #[test]
    fn printf_takes_windbg_comma_separated_arguments() {
        let parse = |tail: &str| parse_printf_tail(tail).map(|(_, args)| args);
        // Spaces belong to the expression, and commas nest in parentheses.
        assert_eq!(
            parse(r#""%p %d\n", poi(@rcx + 8), (1, 2) , 3"#),
            Some(vec!["poi(@rcx + 8)".into(), "(1, 2)".into(), "3".into()])
        );
        // A comma inside the format string is text; the old space form stays.
        assert_eq!(
            parse(r#""a, %d" 0n42 7"#),
            Some(vec!["0n42".into(), "7".into()])
        );
        assert_eq!(parse(r#""%d", 1,"#), None);
        assert_eq!(parse(r#""%d", , 1"#), None);
    }

    #[test]
    fn printf_keeps_literal_strings_separate_from_numeric_expressions() {
        let session = session_over_memory(0x1000, &[0; 8]);
        let result = format_printf(
            "%s=%u %%",
            &["index".into(), "0n27+1".into()],
            &session.target,
            NumberRadix::Hexadecimal,
        )
        .unwrap();
        assert_eq!(result, "index=28 %");
    }
}
