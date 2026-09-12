use std::collections::BTreeMap;
use std::io::IsTerminal;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::{Expr, NumberRadix};
use crate::kuser_shared::{
    read_interrupt_time, read_nt_build_number, read_nt_major_version, read_nt_minor_version,
    read_nt_product_type, read_system_time,
};
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::output;
use crate::target::Target;
use crate::triage_report::filetime_to_iso;
use crate::types::VirtAddr;

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
    summary: "Display or set the default numeric radix for REPL expressions.",
}

repl_command! {
    cmd_version();
    names: ["vertarget", "version"],
    usage: "vertarget",
    summary: "Display target, kernel, symbol, processor, and debugger version information.",
}

repl_command! {
    cmd_time();
    names: [".time"],
    usage: ".time",
    summary: "Display target UTC time and system uptime.",
}

repl_command! {
    cmd_echo;
    names: [".echo", "echo"],
    usage: ".echo <text>",
    summary: "Print text without expression interpretation.",
    style: ExpressionTail,
}

repl_command! {
    cmd_printf;
    names: [".printf"],
    usage: ".printf \"format\" [arguments...]",
    summary: "Format debugger values using WinDbg-style printf specifiers.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_cls();
    names: [".cls"],
    usage: ".cls",
    summary: "Clear the terminal screen when stdout is a terminal.",
}

repl_command! {
    cmd_logopen;
    names: [".logopen"],
    usage: ".logopen <file>",
    summary: "Start a debugger transcript, replacing any existing file.",
}

repl_command! {
    cmd_logappend;
    names: [".logappend"],
    usage: ".logappend <file>",
    summary: "Start a debugger transcript, appending to the file.",
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
    summary: "List commands or display detailed help for one command.",
}

repl_command! {
    cmd_error;
    names: ["!error", "!ntstatus"],
    usage: "!error <code>",
    summary: "Decode an NTSTATUS, Win32, or HRESULT error code.",
    completion: Expression,
}

repl_command! {
    names: ["q", "quit"],
    usage: "q",
    summary: "Exit the application.",
    flow: Quit,
}

impl ReplState<'_> {
    fn cmd_reload_scripts(&mut self) -> Result<()> {
        #[cfg(feature = "python")]
        {
            let py_report = crate::python::embed::load_commands_dir();
            crate::python::embed::print_script_load_report(&py_report);
            *self.caches.user_commands.write().unwrap() = initial_user_commands();
        }
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

    fn cmd_version(&mut self) -> Result<()> {
        print_target_version(
            &self.ctx.target,
            self.ctx.backend.name(),
            &mut *self.ctx.backend,
        );
        outln!();
        Ok(())
    }

    fn cmd_time(&mut self) -> Result<()> {
        let target = &self.ctx.target;
        let (system_time, uptime) = target_times(target);
        outln!("{}", ui::label("target time"));
        match system_time.and_then(filetime_to_iso) {
            Some(time) => outln!("  {} {}", ui::muted("system time"), time),
            None => outln!("  {} unavailable", ui::muted("system time")),
        }
        match uptime {
            Some(ticks) => outln!("  {} {}", ui::muted("uptime"), format_uptime(ticks)),
            None => outln!("  {} unavailable", ui::muted("uptime")),
        }
        outln!();
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
        let text = format_printf(&format, &args, &self.ctx.target, self.radix);
        outln!("{text}");
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
        let Ok(code) = u32::try_from(code) else {
            error!("error code '{text}' exceeds 32 bits");
            return Ok(());
        };
        print_error_code(code, invocation.name == "!ntstatus");
        Ok(())
    }

    pub fn cmd_user(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        #[cfg(feature = "python")]
        if crate::python::embed::has_command(invocation.name) {
            let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
            if let Err(error) = crate::python::embed::dispatch(invocation.name, &args, self.ctx) {
                error!("{}: {}", invocation.name, error);
            }
            return Ok(());
        }

        outln!(
            "unknown command: '{}' (try pressing tab to see available commands)\n",
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
    ("eq", "memory and disassembly"),
    ("ew", "memory and disassembly"),
    ("ea", "memory and disassembly"),
    ("eu", "memory and disassembly"),
    ("eza", "memory and disassembly"),
    ("ezu", "memory and disassembly"),
    ("f", "memory and disassembly"),
    ("s", "memory and disassembly"),
    ("u", "memory and disassembly"),
    ("ub", "memory and disassembly"),
    ("uf", "memory and disassembly"),
    ("!db", "memory and disassembly"),
    ("!dd", "memory and disassembly"),
    ("!dq", "memory and disassembly"),
    ("!dw", "memory and disassembly"),
    ("!eb", "memory and disassembly"),
    ("!ed", "memory and disassembly"),
    ("!eq", "memory and disassembly"),
    ("break", "execution and stack"),
    ("g", "execution and stack"),
    ("gh", "execution and stack"),
    ("gn", "execution and stack"),
    ("gu", "execution and stack"),
    ("k", "execution and stack"),
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
    ("!apc", "execution and stack"),
    ("!stacks", "execution and stack"),
    ("!process", "processes and modules"),
    ("!session", "processes and modules"),
    ("!sprocess", "processes and modules"),
    ("!thread", "processes and modules"),
    ("!vad", "processes and modules"),
    ("~", "processes and modules"),
    ("attach", "processes and modules"),
    ("detach", "processes and modules"),
    ("drivers", "processes and modules"),
    ("ld", "processes and modules"),
    ("lm", "processes and modules"),
    ("lmv", "processes and modules"),
    ("ps", "processes and modules"),
    ("threads", "processes and modules"),
    ("vcpu", "processes and modules"),
    ("!dlls", "user mode"),
    ("!peb", "user mode"),
    ("!teb", "user mode"),
    ("!gle", "user mode"),
    ("ba", "breakpoints and events"),
    ("bc", "breakpoints and events"),
    ("bd", "breakpoints and events"),
    ("be", "breakpoints and events"),
    ("bl", "breakpoints and events"),
    ("bm", "breakpoints and events"),
    ("bp", "breakpoints and events"),
    ("bpc", "breakpoints and events"),
    ("bpp", "breakpoints and events"),
    ("br", "breakpoints and events"),
    ("bs", "breakpoints and events"),
    ("bu", "breakpoints and events"),
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
    ("!idt", "cpu"),
    ("!irql", "cpu"),
    ("!pcr", "cpu"),
    ("!prcb", "cpu"),
    ("!dpcs", "cpu"),
    ("!ready", "cpu"),
    ("!running", "cpu"),
    ("!timer", "cpu"),
    ("!lookaside", "memory manager"),
    ("!memusage", "memory manager"),
    ("!pfn", "memory manager"),
    ("!pool", "memory manager"),
    ("!poolfind", "memory manager"),
    ("!poolused", "memory manager"),
    ("!pte", "memory manager"),
    ("!ptov", "memory manager"),
    ("!vm", "memory manager"),
    ("!vtop", "memory manager"),
    ("callbacks", "objects and I/O"),
    ("!devobj", "objects and I/O"),
    ("!drvobj", "objects and I/O"),
    ("!fileobj", "objects and I/O"),
    ("!handle", "objects and I/O"),
    ("!irp", "objects and I/O"),
    ("!list", "objects and I/O"),
    ("!locks", "objects and I/O"),
    ("!object", "objects and I/O"),
    ("ssdt", "objects and I/O"),
    ("!acl", "security"),
    ("!objsd", "security"),
    ("!sd", "security"),
    ("!sid", "security"),
    ("!token", "security"),
    ("!chkimg", "analysis"),
    ("!error", "analysis"),
    ("?", "symbols, types, and expressions"),
    ("dt", "symbols, types, and expressions"),
    ("dv", "symbols, types, and expressions"),
    ("ev", "symbols, types, and expressions"),
    ("ln", "symbols, types, and expressions"),
    ("set", "symbols, types, and expressions"),
    ("unset", "symbols, types, and expressions"),
    ("vars", "symbols, types, and expressions"),
    ("x", "symbols, types, and expressions"),
];

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

fn dump_system_time(target: &Target) -> Option<u64> {
    target
        .phys
        .dmp_info()
        .and_then(|info| info.system_info.as_ref())
        .map(|info| info.system_time)
        .filter(|time| *time > 0)
        .map(|time| time as u64)
}

fn dump_uptime(target: &Target) -> Option<u64> {
    target
        .phys
        .dmp_info()
        .and_then(|info| info.system_info.as_ref())
        .map(|info| info.system_up_time)
        .filter(|time| *time > 0)
        .map(|time| time as u64)
}

fn target_times(target: &Target) -> (Option<u64>, Option<u64>) {
    let system_time = dump_system_time(target).or_else(|| read_system_time(target));
    let uptime = dump_uptime(target).or_else(|| read_interrupt_time(target));
    (system_time, uptime)
}

fn shared_build_lab(target: &Target) -> Option<String> {
    let guest = target.guest().ok()?;
    let address = guest.ntoskrnl.symbol("NtBuildLab").ok()?.address();
    let mut bytes = [0u8; 128];
    guest
        .ntoskrnl
        .memory()
        .read_bytes(address, &mut bytes)
        .ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn symbol_build_number(target: &Target) -> Option<u64> {
    let guest = target.guest().ok()?;
    guest
        .ntoskrnl
        .symbol("NtBuildNumber")
        .and_then(|symbol| symbol.read::<u16>())
        .ok()
        .map(u64::from)
}

fn format_uptime(ticks: u64) -> String {
    let seconds = ticks / 10_000_000;
    let days = seconds / 86_400;
    let hours = (seconds / 3_600) % 24;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
}

fn print_target_version(
    target: &Target,
    backend: &str,
    client: &mut dyn crate::dbg_backend::DebugBackend,
) {
    let dump_info = target
        .phys
        .dmp_info()
        .and_then(|info| info.system_info.as_ref());
    let major = dump_info
        .map(|info| info.major_version as u64)
        .filter(|value| *value != 0)
        .or_else(|| read_nt_major_version(target));
    let minor = dump_info
        .map(|info| info.minor_version as u64)
        .filter(|value| *value != 0)
        .or_else(|| read_nt_minor_version(target));
    let build = symbol_build_number(target)
        .or_else(|| read_nt_build_number(target))
        .map(|value| value & 0xffff);
    let product = dump_info
        .map(|info| info.product_type as u64)
        .filter(|value| *value != 0)
        .or_else(|| read_nt_product_type(target));
    let (system_time, uptime) = target_times(target);
    let modules = target.kernel_modules().unwrap_or_default();
    let kernel = target
        .kernel_base()
        .and_then(|base| {
            modules
                .iter()
                .find(|module| module.base_address == base)
                .cloned()
        })
        .or_else(|| {
            modules
                .iter()
                .find(|module| module.short_name == "nt")
                .cloned()
        });
    let base = kernel
        .as_ref()
        .map(|module| module.base_address)
        .or_else(|| target.kernel_base());
    let identity = base.and_then(|base| {
        target
            .symbols
            .module_pdb_identity(target.kernel_dtb(), base)
    });
    let processors = crate::cpu_state::processor_count(target).ok().or_else(|| {
        client
            .thread_list()
            .ok()
            .map(|threads| threads.len() as u16)
    });
    let product_label = match product {
        Some(1) => "Workstation",
        Some(2) => "DomainController",
        Some(3) => "Server",
        _ => "unknown",
    };

    outln!("{}", ui::label("target version"));
    outln!(
        "  {} Windows {}.{} build {}{}",
        ui::muted("target"),
        major.map_or_else(|| "?".into(), |value| value.to_string()),
        minor.map_or_else(|| "?".into(), |value| value.to_string()),
        build.map_or_else(|| "?".into(), |value| value.to_string()),
        shared_build_lab(target)
            .map(|lab| format!(" ({lab})"))
            .unwrap_or_default()
    );
    outln!("  {} {}", ui::muted("arch"), target.arch().label());
    match (base, kernel.as_ref().map(|module| module.size)) {
        (Some(base), Some(size)) => outln!(
            "  {} {} size {:#x}",
            ui::muted("kernel"),
            ui::addr(base.0),
            size
        ),
        (Some(base), None) => outln!(
            "  {} {} size unknown",
            ui::muted("kernel"),
            ui::addr(base.0)
        ),
        _ => outln!("  {} unavailable", ui::muted("kernel")),
    }
    if let Some(identity) = identity {
        outln!(
            "  {} ntoskrnl.pdb GUID {:032X} age {}",
            ui::muted("pdb"),
            identity.guid,
            identity.age
        );
    } else {
        outln!("  {} unavailable", ui::muted("pdb"));
    }
    outln!(
        "  {} {}",
        ui::muted("processors"),
        processors.map_or_else(|| "unknown".into(), |value| value.to_string())
    );
    outln!("  {} {}", ui::muted("product"), product_label);
    outln!(
        "  {} {}",
        ui::muted("uptime"),
        uptime.map_or_else(|| "unknown".into(), format_uptime)
    );
    outln!("  {} {}", ui::muted("backend"), backend);
    outln!("  {} {}", ui::muted("ntoseye"), env!("CARGO_PKG_VERSION"));
    let symbol_path = target
        .symbols
        .symbol_sources()
        .into_iter()
        .map(|source| source.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    outln!("  {} {}", ui::muted("symbol path"), symbol_path);
    if let Some(time) = system_time.and_then(filetime_to_iso) {
        outln!("  {} {}", ui::muted("system time"), time);
    }
}

fn parse_printf_tail(text: &str) -> Option<(String, Vec<String>)> {
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

fn eval_printf_value(text: &str, target: &Target, radix: NumberRadix) -> Option<u64> {
    crate::expr::Expr::eval_with_radix(text, target, radix)
        .ok()
        .map(|value| value.0)
}

fn read_wide_string(target: &Target, address: VirtAddr, max_chars: usize) -> Option<String> {
    let count = max_chars.checked_mul(2)?;
    let mut bytes = vec![0u8; count];
    target
        .current_process()
        .ok()?
        .memory()
        .read_bytes(address, &mut bytes)
        .ok()?;
    let mut text = String::new();
    for chunk in bytes.chunks_exact(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            break;
        }
        text.push(char::from_u32(value as u32).unwrap_or('\u{fffd}'));
    }
    Some(text)
}

fn format_printf(format: &str, args: &[String], target: &Target, radix: NumberRadix) -> String {
    let chars: Vec<char> = format.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    let mut arg_index = 0;
    let emit = |output: &mut String,
                arg_index: &mut usize,
                rendered: Option<String>,
                fallback: &[char]| {
        if let Some(rendered) = rendered {
            output.push_str(&rendered);
            *arg_index += 1;
        } else {
            output.extend(fallback);
        }
    };
    while index < chars.len() {
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
            continue;
        };
        let value = || eval_printf_value(argument, target, radix);
        let fallback = &chars[start..=index];
        match (spec, extended.then_some(chars[index])) {
            ('d', None) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| (value as i64).to_string()),
                fallback,
            ),
            ('u', None) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| value.to_string()),
                fallback,
            ),
            ('x', None) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| format!("{value:x}")),
                fallback,
            ),
            ('p', None) => emit(&mut output, &mut arg_index, value().map(ui::addr), fallback),
            ('c', None) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| {
                    char::from_u32(value as u32)
                        .unwrap_or('\u{fffd}')
                        .to_string()
                }),
                fallback,
            ),
            ('s', None) => emit(
                &mut output,
                &mut arg_index,
                Some(argument.to_string()),
                fallback,
            ),
            ('m', Some('a')) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| {
                    target
                        .read_c_string(VirtAddr(value), PRINTF_C_STRING_LIMIT)
                        .unwrap_or_else(|_| format!("<unreadable {value:#x}>"))
                }),
                fallback,
            ),
            ('m', Some('u')) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| {
                    read_wide_string(target, VirtAddr(value), PRINTF_WIDE_STRING_LIMIT)
                        .unwrap_or_else(|| format!("<unreadable {value:#x}>"))
                }),
                fallback,
            ),
            ('y', None) => emit(
                &mut output,
                &mut arg_index,
                value().map(|value| {
                    target
                        .closest_symbol_current_context(VirtAddr(value))
                        .unwrap_or_else(|| format!("{value:#x}"))
                }),
                fallback,
            ),
            _ => output.extend(chars[start..=index].iter()),
        }
        index += 1;
    }
    output
}

fn print_error_code(code: u32, force_ntstatus: bool) {
    let is_ntstatus = force_ntstatus || code >= 0xc000_0000;
    if is_ntstatus {
        let severity = match code >> 30 {
            0 => "success",
            1 => "informational",
            2 => "warning",
            _ => "error",
        };
        let facility = (code >> 16) & 0x0fff;
        let name = ntstatus_name(code).unwrap_or("STATUS_UNKNOWN");
        outln!("NTSTATUS {code:#010x}: {name}");
        outln!(
            "  severity: {severity}; facility: {facility:#x}; customer: {}",
            if code & 0x2000_0000 != 0 { "yes" } else { "no" }
        );
        return;
    }

    if code & 0x8000_0000 != 0 {
        let severity = "error";
        let facility = (code >> 16) & 0x1fff;
        let win32 = if facility == 7 {
            Some(code & 0xffff)
        } else {
            None
        };
        let name = win32
            .and_then(win32_error_name)
            .unwrap_or("HRESULT_UNKNOWN");
        outln!("HRESULT {code:#010x}: {name}");
        outln!(
            "  severity: {severity}; facility: {facility:#x}; customer: {}",
            if code & 0x2000_0000 != 0 { "yes" } else { "no" }
        );
        if let Some(win32) = win32 {
            outln!("  Win32 code: {win32} ({win32:#x})");
        }
        return;
    }

    let name = win32_error_name(code).unwrap_or("ERROR_UNKNOWN");
    outln!("Win32 error {code} ({code:#x}): {name}");
}
