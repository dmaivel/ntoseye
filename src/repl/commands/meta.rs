use std::collections::BTreeMap;
use std::io::IsTerminal;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::{Expr, NumberRadix};
use crate::layout::utf16le_nul_terminated;
use crate::output;
#[cfg(feature = "python")]
use crate::python::embed;
use crate::target::Target;
use crate::target::meta::{
    ErrorCodeDetail, TargetTimeDetail, TargetVersionDetail, decode_error_code,
    decode_error_code_as_ntstatus,
};
use crate::triage_report::time::filetime_to_iso;
use crate::types::{Arch, CodeMachine, VirtAddr};

use crate::repl::*;

const PRINTF_C_STRING_LIMIT: usize = 4096;
const PRINTF_WIDE_STRING_LIMIT: usize = 2048;

repl_command! {
    cmd_reload_scripts();
    names: ["reload-scripts"],
    usage: "reload-scripts",
    summary: "Reload custom commands and aliases.",
}

repl_command! {
    cmd_radix;
    names: ["n"],
    usage: "n [8|10|16]",
    summary: "Show or set the default numeric radix for REPL expressions.",
}

repl_command! {
    cmd_effmach;
    names: [".effmach"],
    usage: ".effmach [x86|amd64|arm64|auto|.]",
    summary: "Show or set the effective code machine.",
    details: "With no argument, shows the selected machine. x86, amd64, and arm64 (on an ARM64 target only) make u, ub, uf, and editor disassembly decode all code as that instruction set, and auto or . goes back to selection by context and image. This selection covers the x86 images of a WOW64 program and, on ARM64, also an emulated x64 image and the x64 ranges of an ARM64X/ARM64EC hybrid. x86 also makes ds/dS read 32-bit (WOW64) string descriptors.",
}

repl_command! {
    cmd_version();
    names: ["vertarget", "version"],
    usage: "vertarget",
    summary: "Show version information for the target, kernel, symbols, processor, and debugger.",
}

repl_command! {
    cmd_time();
    names: [".time"],
    usage: ".time",
    summary: "Show the target UTC time and the system uptime.",
}

repl_command! {
    cmd_echo;
    names: [".echo", "echo"],
    usage: ".echo <text>",
    summary: "Print text without evaluating expressions in it.",
    style: ExpressionTail,
}

repl_command! {
    cmd_echotime();
    names: [".echotime"],
    usage: ".echotime",
    summary: "Print the current date and time of the host in UTC.",
}

repl_command! {
    cmd_printf;
    names: [".printf"],
    usage: ".printf \"format\" [, argument]...",
    summary: "Format debugger values with WinDbg-style printf specifiers.",
    details: "Put the arguments after the format and separate them with commas, as in WinDbg (`.printf \"%p %d\\n\", poi(@rcx + 8), @$t0`). If each argument is one word, you can separate them with spaces.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_cls();
    names: [".cls"],
    usage: ".cls",
    summary: "Clear the terminal screen if stdout is a terminal.",
}

repl_command! {
    cmd_logopen;
    names: [".logopen"],
    usage: ".logopen <file>",
    summary: "Start a debugger transcript and replace any existing file.",
}

repl_command! {
    cmd_logappend;
    names: [".logappend"],
    usage: ".logappend <file>",
    summary: "Start a debugger transcript and append it to the file.",
}

repl_command! {
    cmd_logclose();
    names: [".logclose"],
    usage: ".logclose",
    summary: "Close the debugger transcript.",
}

repl_command! {
    cmd_help;
    names: [".hh", "help", ".help"],
    usage: ".hh [command]",
    summary: "List commands or show detailed help for one command.",
}

repl_command! {
    cmd_error;
    names: ["!error", "!ntstatus"],
    usage: "!error <code>",
    summary: "Decode an NTSTATUS, Win32, or HRESULT error code.",
    completion: Expression,
}

repl_command! {
    names: ["q", "quit", "qd"],
    usage: "q",
    summary: "Exit, remove the breakpoints of this session, and leave the guest running.",
    details: "This is the WinDbg qd command (quit and detach), and ntoseye also accepts qd. If this session halted the guest, q resumes it. If q cannot remove a breakpoint from the guest, it leaves the guest halted, because if q resumed that guest, the breakpoint could trap when there is no debugger.",
    flow: Quit,
}

impl ReplState<'_> {
    fn cmd_reload_scripts(&mut self) -> Result<()> {
        #[cfg(feature = "python")]
        {
            let py_report = embed::load_commands_dir();
            embed::print_script_load_report(&py_report);
            *self.caches.user_commands.write().unwrap() = initial_user_commands();
        }
        #[cfg(not(feature = "python"))]
        print_python_commands_notice();
        let alias_report = self.reload_aliases();
        print_alias_load_report(&alias_report);
        Ok(())
    }

    fn cmd_radix(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(value) = invocation.arg(0) {
            self.radix = match value {
                "8" => NumberRadix::Octal,
                "10" => NumberRadix::Decimal,
                "16" => NumberRadix::Hexadecimal,
                _ => {
                    error!("invalid radix '{value}' (use 8, 10, or 16)");
                    return Ok(());
                }
            };
        }

        let name = match self.radix {
            NumberRadix::Octal => "octal",
            NumberRadix::Decimal => "decimal",
            NumberRadix::Hexadecimal => "hexadecimal",
        };
        outln!("radix {} ({name})\n", self.radix.value());
        Ok(())
    }

    fn cmd_effmach(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }

        if let Some(machine) = invocation.arg(0) {
            let machine = machine.to_ascii_lowercase();
            self.ctx.target.effmach = match machine.as_str() {
                "x86" => Some(CodeMachine::X86),
                "amd64" => Some(CodeMachine::Amd64),
                "arm64" if self.ctx.target.arch() == Arch::Arm64 => Some(CodeMachine::Arm64),
                "arm64" => {
                    error!("an AMD64 target runs no ARM64 code; use x86, amd64, or auto");
                    return Ok(());
                }
                "." | "auto" => None,
                _ => {
                    error!(
                        "invalid effective machine '{machine}' (use x86, amd64, arm64, or auto)"
                    );
                    return Ok(());
                }
            };
        }

        let machine = self.ctx.target.effmach.map_or("auto", CodeMachine::label);
        outln!("effective machine: {machine}\n");
        Ok(())
    }

    fn cmd_version(&mut self) -> Result<()> {
        let detail = self.ctx.target_version()?;
        print_target_version(&detail);
        outln!();
        Ok(())
    }

    fn cmd_time(&mut self) -> Result<()> {
        let detail = self.ctx.target.target_time()?;
        print_target_time(&detail);
        outln!();
        Ok(())
    }

    fn cmd_echotime(&mut self) -> Result<()> {
        const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos() / 100).ok())
            .and_then(|ticks| filetime_to_iso(ticks.checked_add(FILETIME_UNIX_EPOCH)?));
        match now {
            Some(now) => outln!("Debugger (not debuggee) time: {now}\n"),
            None => error!("the host clock is outside the representable range"),
        }
        Ok(())
    }

    fn cmd_echo(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut text = invocation.raw_tail;
        if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
            text = &text[1..text.len() - 1];
        }
        outln!("{text}");
        Ok(())
    }

    fn cmd_printf(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some((format, args)) = parse_printf_tail(invocation.raw_tail) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        // An unreadable argument is reported, not propagated: `.printf` is
        // the body of a log point, and a single bad read must not tear down
        // the session that is running it.
        let text = match format_printf(&format, &args, &self.ctx.target, self.radix) {
            Ok(text) => text,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        // WinDbg's `.printf` emits exactly the format's characters, which is
        // why its examples end in `\n`; appending one here would double it.
        out!("{text}");
        Ok(())
    }

    fn cmd_cls(&mut self) -> Result<()> {
        if std::io::stdout().is_terminal() {
            out!("\x1b[2J\x1b[H");
        }
        Ok(())
    }

    fn cmd_logopen(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.open_log_file(&invocation, false)
    }

    fn cmd_logappend(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.open_log_file(&invocation, true)
    }

    fn open_log_file(&mut self, invocation: &CommandInvocation<'_>, append: bool) -> Result<()> {
        let Some(path) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match output::open_log(path, append) {
            Ok(()) => outln!(
                "log {} {}\n",
                if append { "appending to" } else { "opened" },
                path
            ),
            Err(error) => error!("failed to open log '{}': {error}", path),
        }
        Ok(())
    }

    fn cmd_logclose(&mut self) -> Result<()> {
        output::close_log();
        outln!("log closed\n");
        Ok(())
    }

    fn cmd_help(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(name) = invocation.arg(0) {
            if let Some((_, help, _)) = self
                .caches
                .user_commands
                .read()
                .unwrap()
                .iter()
                .find(|(command, _, _)| command == name)
            {
                outln!("{name}\n{help}\n");
                return Ok(());
            }
            if let Some((_, expansion)) = self
                .aliases
                .entries()
                .into_iter()
                .find(|(alias, _)| alias == name)
            {
                outln!("alias {name} {expansion}\n");
                return Ok(());
            }
            if command_registry().get(name).is_none() {
                error!("unknown command '{name}'");
            } else {
                outln!("{}\n", command_help(name));
            }
            return Ok(());
        }

        let mut groups: BTreeMap<&'static str, BTreeMap<&'static str, &'static CommandSpec>> =
            BTreeMap::new();
        for (_, spec) in command_registry().command_names() {
            let canonical = spec.names[0];
            groups
                .entry(command_category(canonical))
                .or_default()
                .insert(canonical, spec);
        }
        for (category, specs) in groups {
            outln!("{}", ui::label(category));
            for (_, spec) in specs {
                let aliases = spec.names[1..].join(", ");
                if aliases.is_empty() {
                    outln!("  {:<24} {}", spec.names[0], spec.summary);
                } else {
                    outln!(
                        "  {:<24} {} (aliases: {})",
                        spec.names[0],
                        spec.summary,
                        aliases
                    );
                }
            }
            outln!();
        }

        let user_commands = self.caches.user_commands.read().unwrap().clone();
        if !user_commands.is_empty() {
            outln!("{}", ui::label("python commands"));
            for (name, help, _) in user_commands {
                outln!("  {:<24} {}", name, help.lines().next().unwrap_or(""));
            }
            outln!();
        }
        let aliases = self.aliases.entries();
        if !aliases.is_empty() {
            outln!("{}", ui::label("user aliases"));
            for (name, expansion) in aliases {
                outln!("  {name:<24} {expansion}");
            }
            outln!();
        }
        Ok(())
    }

    fn cmd_error(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let code = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(value) => value.0,
            Err(error) => {
                error!("invalid error code '{text}': {error}");
                return Ok(());
            }
        };
        if u32::try_from(code).is_err() {
            error!("error code '{text}' exceeds 32 bits");
            return Ok(());
        }
        let detail = if invocation.name == "!ntstatus" {
            decode_error_code_as_ntstatus(code)
        } else {
            decode_error_code(code)
        };
        print_error_code(&detail);
        Ok(())
    }

    pub fn cmd_user(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        #[cfg(feature = "python")]
        if embed::has_command(invocation.name) {
            let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
            if let Err(error) = embed::dispatch(invocation.name, &args, self.ctx) {
                error!("{}: {}", invocation.name, error);
            }
            return Ok(());
        }

        error!(
            "unknown command '{}' (try pressing tab to see available commands)",
            invocation.name
        );

        Ok(())
    }
}

const COMMAND_CATEGORIES: &[(&str, &str)] = &[
    ("dS", "memory and disassembly"),
    ("dW", "memory and disassembly"),
    ("da", "memory and disassembly"),
    ("db", "memory and disassembly"),
    ("dc", "memory and disassembly"),
    ("dd", "memory and disassembly"),
    ("dds", "memory and disassembly"),
    ("df", "memory and disassembly"),
    ("dl", "memory and disassembly"),
    ("dq", "memory and disassembly"),
    ("dp", "memory and disassembly"),
    ("dpp", "memory and disassembly"),
    ("dqs", "memory and disassembly"),
    ("ds", "memory and disassembly"),
    ("du", "memory and disassembly"),
    ("dw", "memory and disassembly"),
    ("dyb", "memory and disassembly"),
    ("eb", "memory and disassembly"),
    ("ed", "memory and disassembly"),
    ("ef", "memory and disassembly"),
    ("eq", "memory and disassembly"),
    ("ew", "memory and disassembly"),
    ("ea", "memory and disassembly"),
    ("eu", "memory and disassembly"),
    ("eza", "memory and disassembly"),
    ("ezu", "memory and disassembly"),
    ("c", "memory and disassembly"),
    ("f", "memory and disassembly"),
    ("m", "memory and disassembly"),
    ("s", "memory and disassembly"),
    ("u", "memory and disassembly"),
    ("ub", "memory and disassembly"),
    ("#", "memory and disassembly"),
    ("uf", "memory and disassembly"),
    ("!db", "memory and disassembly"),
    ("!dd", "memory and disassembly"),
    ("!dq", "memory and disassembly"),
    ("!dw", "memory and disassembly"),
    ("!eb", "memory and disassembly"),
    ("!ed", "memory and disassembly"),
    ("!eq", "memory and disassembly"),
    ("!search", "memory and disassembly"),
    ("ib", "memory and disassembly"),
    ("iw", "memory and disassembly"),
    ("id", "memory and disassembly"),
    ("ob", "memory and disassembly"),
    ("ow", "memory and disassembly"),
    ("od", "memory and disassembly"),
    ("break", "execution and stack"),
    ("g", "execution and stack"),
    ("gh", "execution and stack"),
    ("gn", "execution and stack"),
    ("gu", "execution and stack"),
    ("kn", "execution and stack"),
    ("kd", "execution and stack"),
    ("pa", "execution and stack"),
    ("p", "execution and stack"),
    ("pc", "execution and stack"),
    ("ph", "execution and stack"),
    ("pt", "execution and stack"),
    ("r", "execution and stack"),
    ("t", "execution and stack"),
    ("ta", "execution and stack"),
    ("tc", "execution and stack"),
    ("th", "execution and stack"),
    ("tt", "execution and stack"),
    ("wt", "execution and stack"),
    ("!analyze", "analysis"),
    (".bugcheck", "analysis"),
    ("!apc", "execution and stack"),
    ("!stacks", "execution and stack"),
    ("!findstack", "execution and stack"),
    ("!uniqstack", "execution and stack"),
    ("!process", "processes and modules"),
    (".vtl", "processes and modules"),
    ("!trustlets", "processes and modules"),
    ("!hvpartitions", "processes and modules"),
    ("!hvvps", "processes and modules"),
    ("!hvept", "processes and modules"),
    ("!hveptdiff", "processes and modules"),
    ("!hvcalls", "processes and modules"),
    ("!hvcall", "processes and modules"),
    ("!hvvmcs", "processes and modules"),
    ("!hvr", "processes and modules"),
    ("!hvd", "processes and modules"),
    ("!hvu", "processes and modules"),
    ("!session", "processes and modules"),
    ("!sprocess", "processes and modules"),
    ("!thread", "processes and modules"),
    ("!vad", "processes and modules"),
    (".effmach", "processes and modules"),
    ("~", "processes and modules"),
    ("attach", "processes and modules"),
    ("detach", "processes and modules"),
    ("drivers", "processes and modules"),
    ("ld", "processes and modules"),
    ("lm", "processes and modules"),
    ("!dh", "processes and modules"),
    ("lmv", "processes and modules"),
    ("!lmi", "processes and modules"),
    ("ps", "processes and modules"),
    ("!for_each_process", "processes and modules"),
    ("!for_each_thread", "processes and modules"),
    ("!for_each_module", "processes and modules"),
    ("threads", "processes and modules"),
    ("vcpu", "processes and modules"),
    ("!dlls", "user mode"),
    ("!heap", "user mode"),
    ("!peb", "user mode"),
    ("!teb", "user mode"),
    ("!gle", "user mode"),
    ("ba", "breakpoints and events"),
    ("bc", "breakpoints and events"),
    ("bd", "breakpoints and events"),
    ("be", "breakpoints and events"),
    ("bl", "breakpoints and events"),
    (".bpcmds", "breakpoints and events"),
    ("gc", "breakpoints and events"),
    ("bm", "breakpoints and events"),
    ("bp", "breakpoints and events"),
    ("bpc", "breakpoints and events"),
    ("bpp", "breakpoints and events"),
    ("br", "breakpoints and events"),
    ("bs", "breakpoints and events"),
    ("bsc", "breakpoints and events"),
    ("bu", "breakpoints and events"),
    ("!hvbp", "breakpoints and events"),
    ("!hvexit", "breakpoints and events"),
    ("sx", "breakpoints and events"),
    ("sxd", "breakpoints and events"),
    ("sxe", "breakpoints and events"),
    ("sxi", "breakpoints and events"),
    ("sxn", "breakpoints and events"),
    ("sxr", "breakpoints and events"),
    ("rdmsr", "cpu"),
    ("wrmsr", "cpu"),
    ("!cpuinfo", "cpu"),
    ("!gdt", "cpu"),
    ("dg", "cpu"),
    ("!idt", "cpu"),
    ("!irql", "cpu"),
    ("!pcr", "cpu"),
    ("!prcb", "cpu"),
    ("!dpcs", "cpu"),
    ("!exqueue", "cpu"),
    ("!ready", "cpu"),
    ("!running", "cpu"),
    ("!timer", "cpu"),
    ("!ca", "memory manager"),
    ("!filecache", "memory manager"),
    ("!qlocks", "cpu"),
    ("!ipi", "cpu"),
    ("!lookaside", "memory manager"),
    ("!mdl", "memory manager"),
    ("!memusage", "memory manager"),
    ("!pfn", "memory manager"),
    ("!pool", "memory manager"),
    ("!poolfind", "memory manager"),
    ("!poolused", "memory manager"),
    ("!poolval", "memory manager"),
    ("!pte", "memory manager"),
    ("!ptov", "memory manager"),
    ("!sysptes", "memory manager"),
    ("!vm", "memory manager"),
    ("!vprot", "memory manager"),
    ("!vtop", "memory manager"),
    ("callbacks", "objects and I/O"),
    ("!alpc", "objects and I/O"),
    ("!devnode", "objects and I/O"),
    ("!devobj", "objects and I/O"),
    ("!devstack", "objects and I/O"),
    ("!drvobj", "objects and I/O"),
    ("!fileobj", "objects and I/O"),
    ("!fltkd.filters", "objects and I/O"),
    ("!fltkd.instances", "objects and I/O"),
    ("!fltkd.volumes", "objects and I/O"),
    ("!handle", "objects and I/O"),
    ("!htrace", "objects and I/O"),
    ("!irp", "objects and I/O"),
    ("!irpfind", "objects and I/O"),
    ("!job", "processes and modules"),
    ("!zombies", "processes and modules"),
    ("!list", "objects and I/O"),
    ("!locks", "objects and I/O"),
    ("!object", "objects and I/O"),
    ("!pnptriage", "objects and I/O"),
    ("!vpb", "objects and I/O"),
    ("!pcitree", "objects and I/O"),
    ("!pci", "objects and I/O"),
    ("ssdt", "objects and I/O"),
    ("!wdfkd.wdfdevice", "objects and I/O"),
    ("!wdfkd.wdfdriverinfo", "objects and I/O"),
    ("!wdfkd.wdfhandle", "objects and I/O"),
    ("!wdfkd.wdfldr", "objects and I/O"),
    ("!wdfkd.wdflogdump", "objects and I/O"),
    ("!wdfkd.wdfqueue", "objects and I/O"),
    ("!acl", "security"),
    ("!objsd", "security"),
    ("!sd", "security"),
    ("!sid", "security"),
    ("!token", "security"),
    ("!chkimg", "analysis"),
    ("!error", "analysis"),
    ("!gflag", "analysis"),
    ("!verifier", "analysis"),
    ("!wmitrace.logdump", "analysis"),
    ("!wmitrace.logger", "analysis"),
    ("!wmitrace.logsave", "analysis"),
    ("!wmitrace.strdump", "analysis"),
    ("?", "symbols, types, and expressions"),
    ("dt", "symbols, types, and expressions"),
    ("dv", "symbols, types, and expressions"),
    ("ln", "symbols, types, and expressions"),
    ("set", "symbols, types, and expressions"),
    ("unset", "symbols, types, and expressions"),
    ("vars", "symbols, types, and expressions"),
    ("x", "symbols, types, and expressions"),
    (".frame", "execution and stack"),
    ("!for_each_frame", "execution and stack"),
    (".fnent", "execution and stack"),
    (".cxr", "execution and stack"),
    (".ecxr", "execution and stack"),
    (".exr", "execution and stack"),
    (".trap", "execution and stack"),
    (".vtlcxr", "execution and stack"),
    (".thread", "execution and stack"),
    (".process", "processes and modules"),
    (".context", "processes and modules"),
    (".readmem", "memory and disassembly"),
    (".writemem", "memory and disassembly"),
    (".pagein", "memory and disassembly"),
    ("!address", "memory and disassembly"),
    (".reload", "symbols, types, and expressions"),
    (".sympath", "symbols, types, and expressions"),
    (".sympath+", "symbols, types, and expressions"),
    (".symfix", "symbols, types, and expressions"),
    (".srcpath", "symbols, types, and expressions"),
    (".srcpath+", "symbols, types, and expressions"),
    (".fetchimage", "symbols, types, and expressions"),
    ("ls", "symbols, types, and expressions"),
    ("lsa", "symbols, types, and expressions"),
    (".formats", "symbols, types, and expressions"),
    ("n", "symbols, types, and expressions"),
    ("irps", "objects and I/O"),
    (".crash", "target control"),
    (".reboot", "target control"),
    (".dump", "target control"),
    (".kdfiles", "target control"),
    (".lastevent", "target control"),
    (".time", "target control"),
    ("vertarget", "target control"),
    ("status", "target control"),
    ("capabilities", "target control"),
    ("!dbgprint", "target control"),
    (".cls", "session"),
    (".echo", "session"),
    (".echotime", "session"),
    (".printf", "session"),
    (".foreach", "session"),
    (".if", "session"),
    (".elsif", "session"),
    (".else", "session"),
    (".while", "session"),
    (".for", "session"),
    (".do", "session"),
    (".break", "session"),
    (".continue", "session"),
    (".block", "session"),
    ("j", "session"),
    ("$<", "session"),
    ("$$", "session"),
    (".sleep", "session"),
    (".hh", "session"),
    (".logopen", "session"),
    (".logappend", "session"),
    (".logclose", "session"),
    (".shell", "session"),
    ("ad", "session"),
    ("al", "session"),
    ("as", "session"),
    ("reload-scripts", "session"),
    ("q", "session"),
];

/// Every built-in command's help as JSON, for the documentation site's
/// generated reference: `[{"category", "names", "usage", "summary",
/// "details"}]` (`details` may be null), grouped as `.hh` groups them and
/// sorted by category, then canonical name.
pub fn command_reference_json() -> String {
    let mut specs: Vec<&CommandSpec> = COMMANDS.iter().collect();
    specs.sort_by_key(|spec| (command_category(spec.names[0]), spec.names[0]));
    let entries: Vec<String> = specs
        .into_iter()
        .map(|spec| {
            let names: Vec<String> = spec.names.iter().map(|name| json_string(name)).collect();
            format!(
                "{{\"category\":{},\"names\":[{}],\"usage\":{},\"summary\":{},\"details\":{}}}",
                json_string(command_category(spec.names[0])),
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

fn command_category(name: &str) -> &'static str {
    if let Some((_, category)) = COMMAND_CATEGORIES
        .iter()
        .find(|(canonical, _)| *canonical == name)
    {
        return category;
    }
    if name.starts_with('.') {
        "dot commands"
    } else if name.starts_with('!') {
        "extension commands"
    } else {
        "general"
    }
}

fn print_target_version(detail: &TargetVersionDetail) {
    outln!("{}", ui::label("target version"));
    outln!(
        "  {} Windows {}.{} build {}{}",
        ui::muted("target"),
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
    outln!("  {} {}", ui::muted("arch"), detail.architecture);
    if let Some(kernel) = &detail.kernel {
        match kernel.size {
            Some(size) => outln!(
                "  {} {} size {:#x}",
                ui::muted("kernel"),
                ui::addr(kernel.base.0),
                size
            ),
            None => outln!(
                "  {} {} size unknown",
                ui::muted("kernel"),
                ui::addr(kernel.base.0)
            ),
        }
    } else {
        outln!("  {} unavailable", ui::muted("kernel"));
    }
    let pdb_guid = detail
        .kernel
        .as_ref()
        .and_then(|kernel| kernel.pdb_guid.as_deref());
    let pdb_age = detail.kernel.as_ref().and_then(|kernel| kernel.pdb_age);
    if let (Some(guid), Some(age)) = (pdb_guid, pdb_age) {
        outln!(
            "  {} ntoskrnl.pdb GUID {} age {}",
            ui::muted("pdb"),
            guid,
            age
        );
    } else {
        outln!("  {} unavailable", ui::muted("pdb"));
    }
    if let Some(kernel) = &detail.kernel {
        if let Some(version) = &kernel.file_version {
            outln!("  {} file version {}", ui::muted("kernel"), version);
        }
        if let Some(version) = &kernel.product_version {
            outln!("  {} product version {}", ui::muted("kernel"), version);
        }
    }
    outln!(
        "  {} {}",
        ui::muted("processors"),
        detail
            .processors
            .map_or_else(|| "unknown".to_string(), |value| value.to_string())
    );
    outln!("  {} {}", ui::muted("product"), detail.product);
    outln!(
        "  {} {}",
        ui::muted("uptime"),
        detail.time.uptime.as_deref().unwrap_or("unknown")
    );
    outln!(
        "  {} {}",
        ui::muted("backend"),
        detail.backend.as_deref().unwrap_or("unknown")
    );
    outln!("  {} {}", ui::muted("ntoseye"), detail.debugger_version);
    outln!("  {} {}", ui::muted("symbol path"), detail.symbol_path);
    outln!(
        "  {} {}",
        ui::muted("symbol status"),
        detail.symbol_status.as_deref().unwrap_or("unknown")
    );
    if let Some(time) = detail.time.system_time_iso.as_deref() {
        outln!("  {} {}", ui::muted("system time"), time);
    }
    if let Some(dump) = &detail.dump {
        outln!(
            "  {} {} (bugcheck: {:#x})",
            ui::muted("dump"),
            if dump.is_triage { "yes" } else { "no" },
            dump.bugcheck_code
        );
        outln!(
            "  {} {} processors, machine {:#x}, service-pack build {}",
            ui::muted("dump metadata"),
            dump.number_processors,
            dump.machine_image_type,
            dump.service_pack_build
        );
        outln!(
            "  {} dtb {:#x}, kernel {:#x}, exception {}",
            ui::muted("dump metadata"),
            dump.directory_table_base.0,
            dump.kernel_base.map_or(0, |base| base.0),
            dump.exception_code
                .map_or_else(|| "none".to_string(), |code| format!("{code:#x}"))
        );
        let parameters = dump
            .bugcheck_parameters
            .iter()
            .map(|value| format!("{value:#x}"))
            .collect::<Vec<_>>()
            .join(", ");
        outln!(
            "  {} parameters [{}]",
            ui::muted("dump metadata"),
            parameters
        );
        outln!(
            "  {} Windows {}.{} product type {}",
            ui::muted("dump metadata"),
            dump.major_version,
            dump.minor_version,
            dump.product_type
        );
        outln!(
            "  {} system time {}, uptime {}",
            ui::muted("dump metadata"),
            dump.system_time
                .map_or_else(|| "unknown".to_string(), |time| format!("{time:#x}")),
            dump.uptime_seconds
                .map_or_else(|| "unknown".to_string(), |seconds| format!("{seconds}s"))
        );
        outln!(
            "  {} triage overflowed {}",
            ui::muted("dump metadata"),
            if dump.triage_overflowed { "yes" } else { "no" }
        );
    }
}

fn print_target_time(detail: &TargetTimeDetail) {
    outln!("{}", ui::label("target time"));
    match (detail.system_time, detail.system_time_iso.as_deref()) {
        (Some(raw), Some(iso)) => outln!("  {} {} ({raw:#x})", ui::muted("system time"), iso),
        (Some(raw), None) => outln!("  {} unavailable ({raw:#x})", ui::muted("system time")),
        _ => outln!("  {} unavailable", ui::muted("system time")),
    }
    match (detail.uptime_seconds, detail.uptime.as_deref()) {
        (Some(seconds), Some(formatted)) => outln!(
            "  {} {} ({seconds} seconds)",
            ui::muted("uptime"),
            formatted
        ),
        _ => outln!("  {} unavailable", ui::muted("uptime")),
    }
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

fn print_error_code(detail: &ErrorCodeDetail) {
    match detail.kind.as_str() {
        "NTSTATUS" => {
            outln!("NTSTATUS {:#010x}: {}", detail.code, detail.name);
            outln!("  {}", detail.description);
        }
        "HRESULT" => {
            outln!("HRESULT {:#010x}: {}", detail.code, detail.name);
            outln!("  {}", detail.description);
            if let Some(win32) = detail.win32_code {
                outln!("  Win32 code: {win32} ({win32:#x})");
            }
        }
        "Win32" => outln!(
            "Win32 error {} ({:#x}): {}",
            detail.code,
            detail.code,
            detail.name
        ),
        _ => outln!(
            "Unknown error code {} ({:#x}): {}",
            detail.code,
            detail.code,
            detail.description
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::output::capture;
    use crate::repl::ReplState;
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

    #[test]
    fn every_command_has_an_explicit_category() {
        let canonical: Vec<&str> = COMMANDS.iter().map(|spec| spec.names[0]).collect();
        let uncategorized: Vec<&str> = canonical
            .iter()
            .copied()
            .filter(|name| !COMMAND_CATEGORIES.iter().any(|(key, _)| key == name))
            .collect();
        assert!(
            uncategorized.is_empty(),
            "commands missing from COMMAND_CATEGORIES: {uncategorized:?}"
        );
        let stale: Vec<&str> = COMMAND_CATEGORIES
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| !canonical.contains(key))
            .collect();
        assert!(
            stale.is_empty(),
            "COMMAND_CATEGORIES keys that are no command's canonical name: {stale:?}"
        );
    }
}
