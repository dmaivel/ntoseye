use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::breakpoints::{
    Breakpoint, BreakpointConfig, BreakpointManager, BreakpointScope, BreakpointSpec,
    HypercallFilter, ThreadScope,
};
use crate::dbg_backend::HwBreakpointAccess;
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix, parse_number_literal_text};
use crate::guest::hypercalls;
use crate::guest::vm_exits::{self, ExitFilter};
use crate::session::InstructionBoundary;
use crate::target::decimal_pid_literal;
use crate::ui;

use crate::repl::commands::thread::ThreadResolution;
use crate::repl::*;
use crate::types::{Dtb, VirtAddr};

repl_command! {
    cmd_bp;
    names: ["bp"],
    usage: "bp [/1] [/a] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <address|file:line> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a breakpoint.",
    details: "The breakpoint replaces the first byte of the instruction at the address, so an instruction must start there. ntoseye confirms one by the symbol at the address, or by decoding from the start of the function around it, and refuses an address inside an instruction. When nothing near the address says where instructions start, or that code cannot be read, bp refuses too, and /a sets the breakpoint without the check. A file:line sets a source breakpoint, as bu does.",
    completion: Expression,
    run_state: Halted,
}
repl_command! {
    cmd_bu;
    names: ["bu"],
    usage: "bu [/1] [/a] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <symbol|file:line> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a deferred symbolic breakpoint.",
    details: "A symbol with an offset, such as mydriver!DriverEntry+0x20, must name the start of an instruction, which ntoseye checks as bp does. Until the symbol resolves nothing says where its instructions start, so bu refuses an offset then, and /a defers the breakpoint without the check. A file:line sets a source breakpoint on each address the line has.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_bm;
    names: ["bm"],
    usage: "bm [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <symbol-pattern> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set deferred symbolic breakpoints on the symbols that match a pattern.",
    details: "Only code symbols match, so bm skips the data symbols that the pattern also matches.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ba;
    names: ["ba"],
    usage: "ba [/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <access><size> <address> [<passes>] [if <expr>] [do <commands>]",
    summary: "Set a hardware (debug-register) breakpoint.",
    details: "The access is e=execute, r=read/write, or w=write, and the size is 1, 2, 4, or 8 bytes. An execute breakpoint has size 1. The command is not available on a dump or on the `memory` backend. Example: ba w4 nt!MyGlobal. In VTL1 (the .vtl 1 view or a vCPU stopped in VTL1), ntoseye accepts only `ba e1`, and only on GDB backends. This breakpoint is global, so you cannot use /p or /t, which name NT processes and threads. Example: .vtl 1; ba e1 securekernel!SkeSelectProcessAddressSpace; g",
    completion: [None, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_hvbp;
    names: ["!hvbp"],
    usage: "!hvbp [/1] [/c <processor>] [/w \"<expr>\"] <code|name> [partition-id [vp-index]] [if <expr>] [do <commands>]",
    summary: "Set a breakpoint that stops on a hypercall to the Windows hypervisor, optionally only from one partition or VP.",
    details: "Sets a hardware execute breakpoint on the hypercall's handler, which the hypervisor's hypercall table gives (see !hvcalls), so it needs the gdb backend and a free debug register. The call is a call code, in the current radix, or its name: the TLFS name (HvCallPostMessage) or the name x hv!* shows (HvCall0004). Many codes share a handler, HvCallUnimplemented's for every code that is not implemented, so at each hit ntoseye reads the caller's call code from its RCX and resumes the target without a stop when it is another. The caller is the VP whose exit the processor handles: the guest partition's VP it serves, or the root partition's VP. With a partition ID, and a VP index in it, the breakpoint stops only for that caller; the IDs use the current radix, and ntoseye refuses a partition or VP that the hypervisor does not have. A hit whose caller ntoseye cannot tell, or whose caller matches but whose registers it cannot read, stops, so the filter does not hide a hit. /1, /c, /w, if, and do work as for ba; a condition sees the caller's registers at its VMCALL (as !hvcall decodes them), not the hypervisor's at the handler, and stops the hit with an error when they are not known. The command takes no pass count: set it with bpp. bl shows the filter. Needs the VM's hv-evmcs enlightenment. Example: !hvbp HvCallSendSyntheticClusterIpi 3; g",
    run_state: Halted,
}

repl_command! {
    cmd_hvexit;
    names: ["!hvexit"],
    usage: "!hvexit [/1] [/c <processor>] [/w \"<expr>\"] <reason> [partition-id [vp-index]] [if <expr>] [do <commands>]",
    summary: "Set a breakpoint that stops on a VM exit to the Windows hypervisor by its reason, optionally only from one partition or VP.",
    details: "Sets a hardware execute breakpoint on the hypervisor's VM-exit entry point (hv!VmExitEntry, the host RIP of every eVMCS), so it needs the gdb backend, the VM's hv-evmcs enlightenment and a free debug register. The reason is a basic exit reason (Intel SDM Appendix C), as a decimal or 0x number, or a name as !hvvps shows it: cpuid, rdmsr, wrmsr, io_instruction, ept_violation, vmcall, hlt. Every exit enters there, so at each hit ntoseye reads the reason from the eVMCS the processor has loaded and resumes the target without a stop when it is another; the guest runs far slower while the breakpoint is set. With a guest partition's ID it rarely stops: that partition's VPs run only when the root partition's NT runs them, which it barely does then; !hvbp stops on a guest's hypercalls without slowing the rest. The caller is the VP whose exit it is, as for !hvbp: with a partition ID, and a VP index in it, the breakpoint stops only for that caller. The condition is evaluated on the caller's registers at its exit and reads the caller's memory. Example: !hvexit cpuid 6 if @rax==0x40000000",
    run_state: Halted,
}

repl_command! {
    cmd_bl();
    names: ["bl"],
    usage: "bl",
    summary: "List all breakpoints.",
    details: "The status column shows `e` for enabled, `d` for disabled, or `o` for owed. An owed breakpoint is a kernel code breakpoint that waits for its page to become resident.",
}

repl_command! {
    cmd_bpcmds();
    names: [".bpcmds"],
    usage: ".bpcmds",
    summary: "Print the commands that set the current breakpoints again.",
    details: "The output has one line for each breakpoint, in ID order. An address breakpoint shows as `bp <address>`, a symbolic or source breakpoint as `bu <symbol>` (as `bm` creates it), a hardware breakpoint as `ba <access><size> <address>`, and a hypercall breakpoint as `!hvbp <code> [partition-id [vp-index]]`, without its pass count, which !hvbp does not take. Each line also has the /1, /p, /t, and /c options of the breakpoint, its condition (as /w), its pass count, and its command string. To set the same breakpoints again, run the lines, either by pasting them or by saving them to a file for `$$<`. WinDbg puts a breakpoint ID in each line, but these lines have none because the ntoseye bp command does not take one, so the new breakpoints get new IDs. A disabled breakpoint comes back enabled.",
}

repl_command! {
    cmd_gc -> Flow;
    names: ["gc"],
    usage: "gc",
    summary: "Resume from the breakpoint that runs the current command string.",
    details: "Use this command only in the command string of a breakpoint, where it stops the command string and resumes the target. You can put it at the end (`bp nt!NtClose \"r rcx; gc\"`) or in a branch (`bp nt!NtClose \"j (@rcx == 0) '' ; 'gc'\"`), and the commands after it do not run. A plain `g` in the command string does the same, as in WinDbg scripts, but ntoseye does not accept `g <address>` or other run control there.",
}

repl_command! {
    cmd_bc;
    names: ["bc"],
    usage: "bc <id|id-id|*>",
    summary: "Clear one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bd;
    names: ["bd"],
    usage: "bd <id|id-id|*>",
    summary: "Disable one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_be;
    names: ["be"],
    usage: "be <id|id-id|*>",
    summary: "Enable one or more breakpoints by ID.",
    completion: Breakpoint,
    run_state: Halted,
}
repl_command! {
    cmd_bpc;
    names: ["bpc"],
    usage: "bpc <id> <condition|clear>",
    summary: "Change or clear a breakpoint condition.",
    completion: [Breakpoint, Expression],
}

repl_command! {
    cmd_bsc;
    names: ["bsc"],
    usage: "bsc <id> <condition> [\"commands\"]",
    summary: "Set the condition and the commands of a breakpoint together.",
    details: "This is the WinDbg update-conditional-breakpoint command. The breakpoint stops only when <condition> is nonzero, and then runs the quoted commands. Use semicolons between the commands (`bsc 0 @rcx==4 \"k; g\"`). If you do not give commands, bsc removes the current commands of the breakpoint.",
    completion: [Breakpoint, Expression],
}

repl_command! {
    cmd_bs;
    names: ["bs", "bpa"],
    usage: "bs <id> <commands|clear>",
    summary: "Set or clear the command action of a breakpoint.",
    completion: Breakpoint,
}

repl_command! {
    cmd_br;
    names: ["br"],
    usage: "br <id> <newid>",
    summary: "Change the ID of a breakpoint.",
    completion: Breakpoint,
}

repl_command! {
    cmd_bpp;
    names: ["bpp"],
    usage: "bpp <id> <passes>",
    summary: "Reset the pass count of a breakpoint.",
    completion: Breakpoint,
}

struct CodeBreakpointArgs {
    spec: String,
    config: BreakpointConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedBreakpointArgs {
    target: String,
    access_spec: Option<String>,
    one_shot: bool,
    /// `/a`: without confirming an instruction starts at the address.
    unchecked: bool,
    pid: Option<u64>,
    thread: Option<u64>,
    processor: Option<u16>,
    pass_count: u64,
    condition: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BreakpointIdSelection {
    All,
    Ids(Vec<u32>),
}

/// An option argument that is a bare number, in the session radix. It takes
/// the same literal grammar as an expression, so `0n7952` is decimal and
/// `0x1f10` is hexadecimal whatever `n` is set to.
fn parse_radix_u64_text(value: &str, radix: NumberRadix, what: &str) -> Result<u64> {
    parse_number_literal_text(value, radix)
        .map_err(|_| Error::InvalidArgument(format!("invalid {what}: {value}")))
}

/// `/p` names a process, never an address, so a bare run of digits is the
/// decimal PID every listing prints and completion inserts. A radix prefix
/// still says what it means, so `0x1f10` and `0n7952` keep working for a PID
/// carried over from an expression.
fn parse_pid_text(value: &str, radix: NumberRadix) -> Result<u64> {
    match decimal_pid_literal(value) {
        Some(pid) => Ok(pid),
        None => parse_radix_u64_text(value, radix, "PID"),
    }
}

/// The options a breakpoint command starts with (`/1`, `/a`, `/p`, `/t`,
/// `/c`, `/w`).
#[derive(Default)]
struct BreakpointOptions {
    one_shot: bool,
    unchecked: bool,
    pid: Option<u64>,
    thread: Option<u64>,
    processor: Option<u16>,
    /// The `/w` condition.
    condition: Option<String>,
}

/// Parse the options `argv` starts with, and the index of the first
/// argument after them.
fn parse_breakpoint_options(
    argv: &[Cow<'_, str>],
    radix: NumberRadix,
    command: &str,
) -> Result<(BreakpointOptions, usize)> {
    let mut index = 0;
    let mut options = BreakpointOptions::default();
    while let Some(arg) = argv.get(index) {
        match arg.as_ref().to_ascii_lowercase().as_str() {
            "/1" => {
                options.one_shot = true;
                index += 1;
            }
            // Only a software breakpoint's site needs an instruction start.
            "/a" if matches!(command, "bp" | "bu") => {
                options.unchecked = true;
                index += 1;
            }
            "/a" => {
                return Err(Error::InvalidArgument(format!(
                    "{command}: /a applies to bp and bu"
                )));
            }
            "/p" => {
                let pid_text = argv.get(index + 1).ok_or_else(|| {
                    Error::InvalidArgument(format!("{command}: /p requires a PID"))
                })?;
                options.pid = Some(parse_pid_text(pid_text.as_ref(), radix)?);
                index += 2;
            }
            "/t" => {
                let thread_text = argv.get(index + 1).ok_or_else(|| {
                    Error::InvalidArgument(format!("{command}: /t requires a thread id or ETHREAD"))
                })?;
                options.thread = Some(parse_radix_u64_text(thread_text.as_ref(), radix, "thread")?);
                index += 2;
            }
            "/c" => {
                let processor_text = argv.get(index + 1).ok_or_else(|| {
                    Error::InvalidArgument(format!("{command}: /c requires a processor number"))
                })?;
                let value = parse_radix_u64_text(processor_text.as_ref(), radix, "processor")?;
                options.processor = Some(u16::try_from(value).map_err(|_| {
                    Error::InvalidArgument(format!("{command}: processor {value} is out of range"))
                })?);
                index += 2;
            }
            "/w" => {
                let condition = argv.get(index + 1).ok_or_else(|| {
                    Error::InvalidArgument(format!("{command}: /w requires an expression"))
                })?;
                options.condition = Some(condition.as_ref().to_string());
                index += 2;
            }
            _ => break,
        }
    }
    Ok((options, index))
}

fn parse_breakpoint_arguments(
    argv: &[Cow<'_, str>],
    radix: NumberRadix,
    command: &str,
    wants_access_spec: bool,
) -> Result<ParsedBreakpointArgs> {
    let (options, mut index) = parse_breakpoint_options(argv, radix, command)?;
    let access_spec = if wants_access_spec {
        let access = argv
            .get(index)
            .ok_or_else(|| Error::InvalidArgument(format!("{command}: missing access/size")))?;
        index += 1;
        Some(access.as_ref().to_string())
    } else {
        None
    };
    let target = argv
        .get(index)
        .ok_or_else(|| Error::InvalidArgument(format!("{command}: missing breakpoint target")))?;
    let target = target.as_ref().to_string();
    index += 1;

    let mut pass_count = 0;
    if let Some(value) = argv.get(index)
        && !value.as_ref().eq_ignore_ascii_case("if")
        && !value.as_ref().eq_ignore_ascii_case("do")
        && let Ok(parsed) = parse_radix_u64_text(value.as_ref(), radix, "pass count")
    {
        pass_count = parsed;
        index += 1;
    }

    let (condition, action) = parse_breakpoint_tail(&argv[index..], options.condition)?;
    Ok(ParsedBreakpointArgs {
        target,
        access_spec,
        one_shot: options.one_shot,
        unchecked: options.unchecked,
        pid: options.pid,
        thread: options.thread,
        processor: options.processor,
        pass_count,
        condition,
        action,
    })
}

/// A `!hvbp` or `!hvexit` command's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHypercallArgs {
    /// The call code or name (`!hvbp`), or the exit reason (`!hvexit`), as
    /// typed.
    call: String,
    partition: Option<u64>,
    vp: Option<u64>,
    one_shot: bool,
    processor: Option<u16>,
    condition: Option<String>,
    action: Option<String>,
}

/// Parse the arguments of `command` (`!hvbp` or `!hvexit`): the options
/// `ba` takes but `/p` and `/t`, the call or exit reason, up to two IDs (the
/// partition, then the VP index), then the condition and action. The IDs
/// are positional, so it takes no pass count.
fn parse_hypercall_arguments(
    argv: &[Cow<'_, str>],
    radix: NumberRadix,
    command: &str,
) -> Result<ParsedHypercallArgs> {
    let (options, mut index) = parse_breakpoint_options(argv, radix, command)?;
    if options.pid.is_some() || options.thread.is_some() {
        return Err(Error::InvalidArgument(format!(
            "{command}: /p and /t name NT processes and threads; a hypervisor breakpoint names its caller by partition ID and VP index"
        )));
    }
    let call = argv
        .get(index)
        .ok_or_else(|| {
            Error::InvalidArgument(format!("{command}: missing hypercall or exit reason"))
        })?
        .to_string();
    index += 1;
    let mut ids = Vec::new();
    while ids.len() < 2
        && let Some(value) = argv.get(index)
        && !value.as_ref().eq_ignore_ascii_case("if")
        && !value.as_ref().eq_ignore_ascii_case("do")
        && let Ok(id) = parse_radix_u64_text(value.as_ref(), radix, "ID")
    {
        ids.push(id);
        index += 1;
    }
    let (condition, action) = parse_breakpoint_tail(&argv[index..], options.condition)?;
    Ok(ParsedHypercallArgs {
        call,
        partition: ids.first().copied(),
        vp: ids.get(1).copied(),
        one_shot: options.one_shot,
        processor: options.processor,
        condition,
        action,
    })
}

/// The call code `!hvbp` names: a hypercall name (see
/// [`hypercalls::hypercall_code`]), else a number in `radix`.
fn hypercall_code_text(text: &str, radix: NumberRadix) -> Result<u16> {
    if let Some(code) = hypercalls::hypercall_code(text) {
        return Ok(code);
    }
    parse_number_literal_text(text, radix)
        .ok()
        .and_then(|code| u16::try_from(code).ok())
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "unknown hypercall '{text}': give a call code, its TLFS name, or the name x hv!* shows"
            ))
        })
}

/// The condition and command action a breakpoint command ends with: `if
/// <expr>` or a bare expression, then `do <commands>` or one quoted
/// argument. `condition` is the one `/w` gave, which `if` may not repeat.
fn parse_breakpoint_tail(
    tail: &[Cow<'_, str>],
    mut condition: Option<String>,
) -> Result<(Option<String>, Option<String>)> {
    let do_index = tail
        .iter()
        .position(|arg| arg.as_ref().eq_ignore_ascii_case("do"));
    let (condition_tail, action_tail) = match do_index {
        Some(index) => (&tail[..index], Some(&tail[index + 1..])),
        None => (tail, None),
    };
    let explicit_if = condition_tail
        .first()
        .is_some_and(|arg| arg.as_ref().eq_ignore_ascii_case("if"));
    let condition_tail = if explicit_if {
        &condition_tail[1..]
    } else {
        condition_tail
    };
    let bare_condition = condition_tail
        .first()
        .is_some_and(|arg| !matches!(arg, Cow::Owned(_)));
    let mut action = None;
    if explicit_if || bare_condition {
        if condition.is_some() {
            return Err(Error::InvalidArgument(
                "breakpoint condition specified more than once".into(),
            ));
        }
        if condition_tail.is_empty() {
            return Err(Error::InvalidArgument(
                "missing breakpoint condition after 'if'".into(),
            ));
        }
        condition = Some(join_breakpoint_args(condition_tail));
    } else if action_tail.is_none() && condition_tail.len() == 1 {
        if let Cow::Owned(action_text) = &condition_tail[0] {
            if action_text.is_empty() {
                return Err(Error::InvalidArgument(
                    "missing breakpoint commands after 'do'".into(),
                ));
            }
            action = Some(action_text.clone());
        }
    } else if !condition_tail.is_empty() {
        return Err(Error::InvalidArgument(
            "invalid breakpoint condition or action".into(),
        ));
    }

    if let Some(action_tail) = action_tail {
        if action_tail.is_empty() {
            return Err(Error::InvalidArgument(
                "missing breakpoint commands after 'do'".into(),
            ));
        }
        let action_text = join_breakpoint_args(action_tail);
        if action_text.is_empty() {
            return Err(Error::InvalidArgument(
                "missing breakpoint commands after 'do'".into(),
            ));
        }
        action = Some(action_text);
    }
    Ok((condition, action))
}

fn join_breakpoint_args(args: &[Cow<'_, str>]) -> String {
    args.iter()
        .map(|arg| arg.as_ref())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `bp`/`bu`/`ba` line that sets a breakpoint described as `args`
/// again: what `.bpcmds` prints, parsed back by [`parse_breakpoint_arguments`].
fn breakpoint_command_line(command: &str, args: &ParsedBreakpointArgs) -> String {
    let mut line = command.to_string();
    if args.one_shot {
        line.push_str(" /1");
    }
    if args.unchecked {
        line.push_str(" /a");
    }
    if let Some(pid) = args.pid {
        line.push_str(&format!(" /p {pid}"));
    }
    if let Some(thread) = args.thread {
        line.push_str(&format!(" /t {thread:#x}"));
    }
    if let Some(processor) = args.processor {
        line.push_str(&format!(" /c {processor:#x}"));
    }
    if let Some(condition) = &args.condition {
        line.push_str(&format!(" /w {}", quote_arg(condition)));
    }
    if let Some(access) = &args.access_spec {
        line.push_str(&format!(" {access}"));
    }
    line.push_str(&format!(" {}", args.target));
    // Zero and one both break on the first hit.
    if args.pass_count > 1 {
        line.push_str(&format!(" {:#x}", args.pass_count));
    }
    if let Some(action) = &args.action {
        line.push_str(&format!(" {}", quote_arg(action)));
    }
    line
}

/// The command and arguments that set `bp` again; `None` for a debugger's
/// internal stop.
fn recreate_breakpoint(bp: &Breakpoint) -> Option<(&'static str, ParsedBreakpointArgs)> {
    if bp.temporary {
        return None;
    }
    let hypervisor = match (&bp.hypercall, &bp.vm_exit) {
        (Some(filter), _) => Some(("!hvbp", u64::from(filter.code), filter.partition, filter.vp)),
        (None, Some(filter)) => Some((
            "!hvexit",
            u64::from(filter.reason),
            filter.partition,
            filter.vp,
        )),
        (None, None) => None,
    };
    if let Some((command, what, partition, vp)) = hypervisor {
        // `!hvbp` and `!hvexit` take the call or reason and its caller's IDs
        // where `ba` takes its address, and no pass count after them.
        let target = [Some(what), partition, vp.map(u64::from)]
            .into_iter()
            .flatten()
            .map(|value| format!("{value:#x}"))
            .collect::<Vec<_>>()
            .join(" ");
        return Some((
            command,
            ParsedBreakpointArgs {
                target,
                access_spec: None,
                one_shot: bp.one_shot,
                unchecked: false,
                pid: None,
                thread: None,
                processor: bp.processor,
                pass_count: 0,
                condition: bp.condition.clone(),
                action: bp.action.clone(),
            },
        ));
    }
    let (command, access_spec, target) = match (&bp.hardware, bp.specification()) {
        (Some(hw), _) => (
            "ba",
            Some(format!("{}{}", hw.access.letter(), hw.len)),
            format!("{:#x}", bp.address.0),
        ),
        (None, Some(spec)) => ("bu", None, spec.to_string()),
        (None, None) => ("bp", None, format!("{:#x}", bp.address.0)),
    };
    let pid = match &bp.scope {
        BreakpointScope::Process { pid, .. } => Some(*pid),
        BreakpointScope::Kernel => None,
    };
    Some((
        command,
        ParsedBreakpointArgs {
            target,
            access_spec,
            one_shot: bp.one_shot,
            unchecked: bp.unchecked,
            pid,
            thread: bp.thread.as_ref().map(|thread| thread.ethread.0),
            processor: bp.processor,
            pass_count: bp.pass_count,
            condition: bp.condition.clone(),
            action: bp.action.clone(),
        },
    ))
}

/// The `bl` table: one row per breakpoint.
fn print_breakpoint_list(bps: &[&Breakpoint]) {
    let mut builder = Builder::default();
    builder.push_record(vec![
        "ID".to_string(),
        "Status".to_string(),
        "Address".to_string(),
        "Pass Count".to_string(),
        "Process/Thread".to_string(),
        "Symbol".to_string(),
        "Condition".to_string(),
        "Action".to_string(),
    ]);

    for bp in bps {
        let pass_count = format!(
            "{:04} ({:04})",
            bp.remaining_pass_count.saturating_add(1),
            bp.pass_count.max(1)
        );
        let symbol = match bp.hardware {
            Some(hw) => format!(
                "watch {}{} {}",
                hw.access.letter(),
                hw.len,
                bp.specification().or(bp.symbol.as_deref()).unwrap_or("-")
            ),
            None => bp
                .specification()
                .or(bp.symbol.as_deref())
                .unwrap_or("-")
                .to_string(),
        };
        builder.push_record(vec![
            ui::bp_id(bp.id),
            match (bp.enabled, bp.awaiting_page_in()) {
                // `o`: enabled and accepted by the target, but the opcode
                // is owed until its page is resident.
                (true, true) => "o",
                (true, false) => "e",
                (false, _) => "d",
            }
            .to_string(),
            bp.resolved_address()
                .map(|address| ui::addr(address.0))
                .unwrap_or_else(|| "-".to_string()),
            pass_count,
            bp.scope_label(),
            symbol,
            bp.condition.as_deref().unwrap_or("-").to_string(),
            bp.action.as_deref().unwrap_or("-").to_string(),
        ]);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::new(0, 2, 0, 0));
    outln!("{table}\n");
}

fn parse_breakpoint_id_selectors(args: &[&str]) -> Result<BreakpointIdSelection> {
    if args.is_empty() {
        return Err(Error::InvalidArgument("missing breakpoint ID".into()));
    }
    if args.len() == 1 && args[0] == "*" {
        return Ok(BreakpointIdSelection::All);
    }
    if args.contains(&"*") {
        return Err(Error::InvalidArgument(
            "'*' cannot be combined with breakpoint IDs".into(),
        ));
    }

    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    for selector in args {
        if let Some((first, last)) = selector.split_once('-') {
            let first = first.parse::<u32>().map_err(|_| {
                Error::InvalidArgument(format!("invalid breakpoint ID range: {selector}"))
            })?;
            let last = last.parse::<u32>().map_err(|_| {
                Error::InvalidArgument(format!("invalid breakpoint ID range: {selector}"))
            })?;
            if first > last {
                return Err(Error::InvalidArgument(format!(
                    "breakpoint ID range must be ascending: {selector}"
                )));
            }
            for id in first..=last {
                if seen.insert(id) {
                    ids.push(id);
                }
            }
        } else {
            let id = selector.parse::<u32>().map_err(|_| {
                Error::InvalidArgument(format!("invalid breakpoint ID: {selector}"))
            })?;
            if seen.insert(id) {
                ids.push(id);
            }
        }
    }
    Ok(BreakpointIdSelection::Ids(ids))
}
fn compile_repl_condition(
    condition: Option<&str>,
    radix: NumberRadix,
) -> Result<Option<Arc<Expr>>> {
    condition
        .map(|text| Expr::parse_with_radix(text, radix).map(Arc::new))
        .transpose()
}

/// Parse a WinDbg-style `ba` access/size token like `w4`, `r1`, `e1`: a leading
/// access letter (`e`/`r`/`w`) followed by the watch width in bytes.
fn parse_hw_breakpoint_spec(spec: &str) -> Result<(HwBreakpointAccess, u8)> {
    let mut chars = spec.chars();
    let access = match chars.next().map(|c| c.to_ascii_lowercase()) {
        Some('e') => HwBreakpointAccess::Execute,
        Some('w') => HwBreakpointAccess::Write,
        Some('r') => HwBreakpointAccess::ReadWrite,
        _ => {
            return Err(Error::InvalidArgument(format!(
                "invalid access in '{spec}' (use e=execute, r=read/write, w=write)"
            )));
        }
    };
    let size: String = chars.collect();
    let len = match size.as_str() {
        // Execute watches are always a single byte; allow the bare `e`.
        "" if matches!(access, HwBreakpointAccess::Execute) => 1,
        "" => {
            return Err(Error::InvalidArgument(format!(
                "missing size in '{spec}' (e.g. ba w4 <address>)"
            )));
        }
        other => other.parse().map_err(|_| {
            Error::InvalidArgument(format!("invalid size '{other}' (use 1, 2, 4, or 8)"))
        })?,
    };
    Ok((access, len))
}

fn apply_breakpoint_updates(
    ids: Vec<u32>,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
    verb: &str,
    mut update: impl FnMut(&mut BreakpointManager, u32) -> Result<()>,
) -> Result<()> {
    let mut changed = false;
    for id in ids {
        match update(breakpoints, id) {
            Ok(()) => {
                changed = true;
                outln!("breakpoint {} {verb}", ui::bp_id(id));
            }
            Err(error) => error!("{error}"),
        }
    }
    if changed {
        caches.refresh_breakpoints(breakpoints);
        outln!();
    }
    Ok(())
}

impl ReplState<'_> {
    fn breakpoint_id_arg(invocation: &CommandInvocation<'_>, command: &str) -> Option<u32> {
        let Some(id_str) = invocation.arg(0) else {
            outln!("{}\n", command_help(command));
            return None;
        };

        match id_str.parse::<u32>() {
            Ok(id) => Some(id),
            Err(_) => {
                error!("invalid breakpoint ID: {}", id_str);
                None
            }
        }
    }
    fn parse_radix_u64(&self, value: &str, what: &str) -> Result<u64> {
        parse_radix_u64_text(value, self.radix, what)
    }

    fn breakpoint_scope(&self, pid: Option<u64>) -> Result<Option<BreakpointScope>> {
        let Some(pid) = pid else {
            return Ok(None);
        };
        let process = self
            .ctx
            .target
            .guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .enumerate_processes()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| Error::InvalidArgument(format!("process {pid} not found")))?;
        Ok(Some(BreakpointScope::process(&process)))
    }

    /// The thread `/t` names, as a filter. Accepts what `.thread` accepts: a
    /// thread id, an ETHREAD, or a KTHREAD.
    fn breakpoint_thread_scope(&mut self, thread: Option<u64>) -> Result<Option<ThreadScope>> {
        let Some(value) = thread else {
            return Ok(None);
        };
        let active = self.ctx.active_thread_map();
        match self.resolve_windows_thread(Some(value), &active)? {
            ThreadResolution::Found(thread) => Ok(Some(ThreadScope::new(&thread))),
            ThreadResolution::Missing => Err(Error::InvalidArgument(format!(
                "no thread matches {value:#x}"
            ))),
            ThreadResolution::Ambiguous(count) => Err(Error::InvalidArgument(format!(
                "{count} threads match {value:#x}; name one by its ETHREAD"
            ))),
        }
    }

    /// The processor `/c` names, rejected here if the guest has no such
    /// processor: a filter on one that never reports is a breakpoint that
    /// silently never fires.
    fn breakpoint_processor_scope(&mut self, processor: Option<u16>) -> Result<Option<u16>> {
        let Some(processor) = processor else {
            return Ok(None);
        };
        let count = crate::cpu_state::processor_count(&self.ctx.target)?;
        if processor >= count {
            return Err(Error::InvalidArgument(format!(
                "processor {processor} does not exist; the guest reports {count}"
            )));
        }
        Ok(Some(processor))
    }

    fn breakpoint_config(&mut self, parsed: ParsedBreakpointArgs) -> Result<BreakpointConfig> {
        let condition_expr = compile_repl_condition(parsed.condition.as_deref(), self.radix)?;
        let scope = self.breakpoint_scope(parsed.pid)?;
        let thread = self.breakpoint_thread_scope(parsed.thread)?;
        let processor = self.breakpoint_processor_scope(parsed.processor)?;
        Ok(BreakpointConfig {
            condition: parsed.condition,
            condition_expr,
            pass_count: parsed.pass_count,
            one_shot: parsed.one_shot,
            action: parsed.action,
            scope,
            thread,
            processor,
            hypercall: None,
            vm_exit: None,
            // A breakpoint set in a partition view becomes the partition's
            // when the session sets it.
            partition: None,
            // `bu <symbol>` breaks at the symbol, as WinDbg does. Only a host
            // whose client expects arguments to be live (DAP) skips ahead.
            skip_prologue: false,
            unchecked: parsed.unchecked,
        })
    }

    fn code_breakpoint_args(
        &mut self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Result<CodeBreakpointArgs> {
        self.ctx.require_software_breakpoints()?;
        let parsed = parse_breakpoint_arguments(&invocation.argv, self.radix, command, false)?;
        let spec = parsed.target.clone();
        Ok(CodeBreakpointArgs {
            spec,
            config: self.breakpoint_config(parsed)?,
        })
    }

    fn report_breakpoint_result(&mut self, result: Result<u32>, label: &str) -> Option<u32> {
        match result {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                outln!("{label} {}\n", ui::bp_id(id));
                Some(id)
            }
            Err(error) => {
                error!("{error}");
                None
            }
        }
    }

    fn cmd_bu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args = match self.code_breakpoint_args(&invocation, "bu") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if BreakpointSpec::source(&args.spec, 0).is_some() {
            self.set_source_breakpoint(args);
            return Ok(());
        }
        if !args.config.unchecked
            && let Err(error) = self.check_symbol_site(&args)
        {
            error!("{error}");
            return Ok(());
        }

        let spec = args.spec.clone();
        let result = self.ctx.breakpoints.add_symbolic(
            &mut *self.ctx.backend,
            &self.ctx.target,
            args.spec,
            args.config,
        );
        if let Some(id) = self.report_breakpoint_result(result, "symbolic breakpoint") {
            let bp = self
                .ctx
                .breakpoints
                .list()
                .into_iter()
                .find(|bp| bp.id == id);
            if bp.is_some_and(|bp| bp.deferred()) {
                outln!(
                    "  {} is deferred until '{}' resolves\n",
                    ui::bp_id(id),
                    spec
                );
            }
        }
        Ok(())
    }

    /// Set a source breakpoint on each address `file:line` has (`bu` and
    /// `bp` given a source line).
    fn set_source_breakpoint(&mut self, args: CodeBreakpointArgs) {
        let spec = args.spec.clone();
        match self.ctx.breakpoints.add_source(
            &mut *self.ctx.backend,
            &self.ctx.target,
            args.spec,
            args.config,
        ) {
            Ok(ids) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                if ids.len() == 1 {
                    let deferred = self
                        .ctx
                        .breakpoints
                        .list()
                        .into_iter()
                        .find(|bp| bp.id == ids[0])
                        .is_some_and(|bp| bp.deferred());
                    if deferred {
                        outln!(
                            "source breakpoint {} deferred until '{}' resolves\n",
                            ui::bp_id(ids[0]),
                            spec
                        );
                    } else {
                        outln!(
                            "source breakpoint {} set for '{}'\n",
                            ui::bp_id(ids[0]),
                            spec
                        );
                    }
                } else {
                    outln!("{} source breakpoints set for '{}'\n", ids.len(), spec);
                }
            }
            Err(error) => error!("{error}"),
        }
    }

    /// Refuse `bu`'s symbol unless an instruction starts where it resolves.
    /// A symbol's own start always does and an offset into one is checked,
    /// but nothing says where the instructions of a symbol that does not
    /// resolve yet start.
    fn check_symbol_site(&self, args: &CodeBreakpointArgs) -> Result<()> {
        let target = &self.ctx.target;
        let scope = args.config.scope.as_ref();
        match BreakpointManager::resolve_symbol_in_scope(target, &args.spec, scope)? {
            Some((_, 0)) => Ok(()),
            Some((address, _)) => self.require_instruction_start(
                BreakpointManager::resolution_dtb(target, scope),
                address,
                "bu",
            ),
            None => match BreakpointSpec::split_symbol_offset(&args.spec) {
                Some((symbol, offset)) if offset != 0 => Err(Error::Breakpoint(format!(
                    "{} does not resolve yet, so ntoseye cannot confirm that an instruction \
                     starts at {}; bu /a defers the breakpoint without the check",
                    symbol.trim(),
                    args.spec
                ))),
                _ => Ok(()),
            },
        }
    }

    /// Refuse a software breakpoint at `address` in the address space `dtb`
    /// unless an instruction starts there (see
    /// [`Session::instruction_boundary`]). `command` names the command that
    /// sets one without the check.
    fn require_instruction_start(&self, dtb: Dtb, address: VirtAddr, command: &str) -> Result<()> {
        let symbols = &self.ctx.target.symbols;
        let name = |address: VirtAddr| {
            symbols
                .format_closest_symbol_for_address(dtb, address)
                .unwrap_or_else(|| format!("{:#x}", address.0))
        };
        let unconfirmed = match self.ctx.instruction_boundary(dtb, address) {
            InstructionBoundary::Start => return Ok(()),
            InstructionBoundary::Inside { instruction, from } => {
                let decoding = if from == instruction {
                    String::new()
                } else {
                    format!(", decoding from {}", name(from))
                };
                return Err(Error::Breakpoint(format!(
                    "{} is inside the instruction at {}{decoding}; a breakpoint there would \
                     corrupt that instruction",
                    name(address),
                    name(instruction)
                )));
            }
            InstructionBoundary::NoAnchor => {
                format!(
                    "nothing near {} says where instructions start",
                    name(address)
                )
            }
            InstructionBoundary::Unreadable { from } => format!(
                "the code from {} to {} cannot be read",
                name(from),
                name(address)
            ),
        };
        Err(Error::Breakpoint(format!(
            "{unconfirmed}, so ntoseye cannot confirm that an instruction starts there; \
             {command} /a sets the breakpoint without the check"
        )))
    }

    fn cmd_bm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const BM_LIMIT: usize = 256;
        let args = match self.code_breakpoint_args(&invocation, "bm") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let set = self
            .ctx
            .add_pattern_breakpoints(&args.spec, args.config.clone(), BM_LIMIT)?;
        for error in &set.errors {
            error!("bm: {error}");
        }
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);
        if set.ids.is_empty() {
            outln!("no code symbols match '{}'\n", args.spec);
        } else {
            let suffix = if set.limited {
                "; results limited to 256, refine the pattern"
            } else {
                ""
            };
            outln!("{} symbolic breakpoint(s) set{suffix}\n", set.ids.len());
        }
        Ok(())
    }

    fn cmd_ba(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let parsed = match parse_breakpoint_arguments(&invocation.argv, self.radix, "ba", true) {
            Ok(parsed) => parsed,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some(spec_str) = parsed.access_spec.as_deref() else {
            error!("ba: missing access/size");
            return Ok(());
        };
        // Resolving these walks NT's process and thread lists, which say
        // nothing about which VTL1 context executes the address.
        if self.ctx.target.in_secure_address_space()
            && (parsed.pid.is_some() || parsed.thread.is_some())
        {
            error!(
                "ba: /p and /t name NT processes and threads; a VTL1 hardware breakpoint is global"
            );
            return Ok(());
        }
        let addr_str = parsed.target.as_str();

        let (access, len) = match parse_hw_breakpoint_spec(spec_str) {
            Ok(parsed) => parsed,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let Some(address) = self.eval_or_report(addr_str) else {
            return Ok(());
        };
        let condition = parsed.condition.clone();
        let config = match self.breakpoint_config(parsed) {
            Ok(config) => config,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };

        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);

        match self
            .ctx
            .add_hardware_breakpoint(address, access, len, symbol.clone(), config)
        {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                outln!(
                    "hardware breakpoint {} ({} {}b) set at {}{}{}\n",
                    ui::bp_id(id),
                    access.label(),
                    len,
                    ui::addr(address.0),
                    symbol
                        .map(|s| format!(" ({})", ui::symbol(&s)))
                        .unwrap_or_default(),
                    condition_label.bright_black(),
                );
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_hvbp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let result = parse_hypercall_arguments(&invocation.argv, self.radix, "!hvbp")
            .and_then(|parsed| self.add_hypercall_breakpoint(parsed));
        self.report_hypervisor_breakpoint("hypercall", result);
        Ok(())
    }

    fn cmd_hvexit(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let result = parse_hypercall_arguments(&invocation.argv, self.radix, "!hvexit")
            .and_then(|parsed| self.add_exit_breakpoint(parsed));
        self.report_hypervisor_breakpoint("VM-exit", result);
        Ok(())
    }

    /// Print a hypervisor breakpoint `!hvbp` or `!hvexit` set, or why not.
    fn report_hypervisor_breakpoint(&mut self, kind: &str, result: Result<u32>) {
        let id = match result {
            Ok(id) => id,
            Err(error) => {
                error!("{error}");
                return;
            }
        };
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);
        if let Some(bp) = self.ctx.breakpoints.get(id) {
            outln!(
                "{kind} breakpoint {} set at {}{}{}\n",
                ui::bp_id(id),
                ui::addr(bp.address.0),
                bp.symbol
                    .as_ref()
                    .map(|symbol| format!(" ({})", ui::symbol(symbol)))
                    .unwrap_or_default(),
                format!(" ({})", bp.scope_label()).bright_black(),
            );
        }
    }

    fn add_hypercall_breakpoint(&mut self, parsed: ParsedHypercallArgs) -> Result<u32> {
        let code = hypercall_code_text(&parsed.call, self.radix)?;
        let (vp, config) = self.hypervisor_breakpoint_config(&parsed)?;
        self.ctx.add_hypercall_breakpoint(
            HypercallFilter {
                code,
                partition: parsed.partition,
                vp,
            },
            config,
        )
    }

    /// The VP index and configuration a `!hvbp` or `!hvexit` command gives.
    fn hypervisor_breakpoint_config(
        &mut self,
        parsed: &ParsedHypercallArgs,
    ) -> Result<(Option<u32>, BreakpointConfig)> {
        let vp = parsed
            .vp
            .map(|vp| {
                u32::try_from(vp)
                    .map_err(|_| Error::InvalidArgument(format!("VP index {vp} is out of range")))
            })
            .transpose()?;
        let config = BreakpointConfig {
            condition_expr: compile_repl_condition(parsed.condition.as_deref(), self.radix)?,
            condition: parsed.condition.clone(),
            one_shot: parsed.one_shot,
            action: parsed.action.clone(),
            processor: self.breakpoint_processor_scope(parsed.processor)?,
            ..BreakpointConfig::default()
        };
        Ok((vp, config))
    }

    fn add_exit_breakpoint(&mut self, parsed: ParsedHypercallArgs) -> Result<u32> {
        let reason = vm_exits::parse_reason(&parsed.call)?;
        let (vp, config) = self.hypervisor_breakpoint_config(&parsed)?;
        self.ctx.add_exit_breakpoint(
            ExitFilter {
                reason,
                partition: parsed.partition,
                vp,
            },
            config,
        )
    }

    /// `bp /p <pid> mod!sym` names the address space the symbol lives in, but
    /// the expression evaluator only knows the inspection scope. When the
    /// evaluation fails and the spec is a plain `mod!sym`, resolve it under
    /// the `/p` process instead, loading that module's symbols on demand.
    fn resolve_symbol_in_scope(
        &self,
        spec: &str,
        scope: Option<&BreakpointScope>,
    ) -> Option<VirtAddr> {
        let Some(BreakpointScope::Process { pid, dtb, .. }) = scope else {
            return None;
        };
        let (module, _) = spec.split_once('!')?;
        let symbols = &self.ctx.target.symbols;
        if let Ok(Some(address)) = symbols.find_symbol_across_modules(*dtb, spec) {
            return Some(address);
        }
        self.ctx
            .target
            .load_process_module_symbols(*pid, *dtb, Some(module.trim()))
            .ok()?;
        symbols.find_symbol_across_modules(*dtb, spec).ok()?
    }

    fn cmd_bp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args = match self.code_breakpoint_args(&invocation, "bp") {
            Ok(args) => args,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let address = match Expr::eval_with_radix(&args.spec, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                match self.resolve_symbol_in_scope(&args.spec, args.config.scope.as_ref()) {
                    Some(address) => address,
                    // `bp queue.c:42` is a source line, which only fails as
                    // an expression.
                    None if BreakpointSpec::source(&args.spec, 0).is_some() => {
                        self.set_source_breakpoint(args);
                        return Ok(());
                    }
                    None => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
        };
        let label_dtb = match args.config.scope.as_ref() {
            Some(BreakpointScope::Process { dtb, .. }) => *dtb,
            _ => self.ctx.target.current_dtb(),
        };
        if !args.config.unchecked
            && let Err(error) = self.require_instruction_start(label_dtb, address, "bp")
        {
            error!("{error}");
            return Ok(());
        }
        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(label_dtb, address);
        match self.ctx.breakpoints.add_configured(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
            symbol.clone(),
            args.config,
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let breakpoint = self
                    .ctx
                    .breakpoints
                    .list()
                    .into_iter()
                    .find(|bp| bp.id == id);
                outln!(
                    "breakpoint {} set at {}{}{}\n",
                    ui::bp_id(id),
                    ui::addr(address.0),
                    symbol
                        .map(|symbol| format!(" ({})", ui::symbol(&symbol)))
                        .unwrap_or_default(),
                    breakpoint
                        .as_ref()
                        .map(|bp| format!(" ({})", bp.scope_label()))
                        .unwrap_or_default()
                        .bright_black(),
                );
                // The target accepted the site into its own table but its page
                // is out, so the opcode is owed. Say so rather than letting the
                // confirmation imply an armed site.
                if breakpoint.is_some_and(|bp| bp.awaiting_page_in()) {
                    outln!(
                        "{}\n",
                        ui::muted(
                            "  site is not resident; the target writes the breakpoint when the \
                             page is paged in (`ba e1` traps a site that never pages in on its \
                             own)"
                        )
                    );
                }
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn selected_breakpoint_ids(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Option<Vec<u32>> {
        let args = invocation
            .argv
            .iter()
            .map(|arg| arg.as_ref())
            .collect::<Vec<_>>();
        let selection = match parse_breakpoint_id_selectors(&args) {
            Ok(selection) => selection,
            Err(error) => {
                if args.is_empty() {
                    outln!("{}\n", command_help(command));
                } else {
                    error!("{error}");
                }
                return None;
            }
        };
        let managed = self.ctx.breakpoints.managed_ids();
        let managed_set = managed.iter().copied().collect::<HashSet<_>>();
        Some(match selection {
            BreakpointIdSelection::All => managed,
            BreakpointIdSelection::Ids(ids) => ids
                .into_iter()
                .filter(|id| managed_set.contains(id))
                .collect(),
        })
    }

    fn cmd_bl(&mut self) -> Result<()> {
        let bps = self.ctx.breakpoints.list();
        if bps.is_empty() {
            outln!("no breakpoints set\n");
            return Ok(());
        }

        #[cfg(feature = "cli")]
        native::render(
            || native::lists::breakpoints(&bps),
            || print_breakpoint_list(&bps),
        );
        #[cfg(not(feature = "cli"))]
        print_breakpoint_list(&bps);
        Ok(())
    }

    fn cmd_bpcmds(&mut self) -> Result<()> {
        for bp in self.ctx.breakpoints.list() {
            if let Some((command, args)) = recreate_breakpoint(bp) {
                outln!("{}", breakpoint_command_line(command, &args));
            }
        }
        Ok(())
    }

    fn cmd_gc(&mut self, invocation: CommandInvocation<'_>) -> Result<Flow> {
        if !invocation.raw_tail.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(Flow::Continue);
        }
        if self.context != DispatchContext::BreakpointAction {
            error!("gc resumes only from a breakpoint's command string; use g");
            return Ok(Flow::Denied);
        }
        Ok(Flow::Jump(Jump::Resume))
    }

    fn cmd_bc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "bc") else {
            return Ok(());
        };
        let (breakpoints, backend, target) = self.ctx.breakpoint_sites();
        apply_breakpoint_updates(
            ids,
            breakpoints,
            &self.caches,
            "cleared",
            |breakpoints, id| breakpoints.remove(backend, target, id),
        )
    }

    fn cmd_bd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "bd") else {
            return Ok(());
        };
        let (breakpoints, backend, target) = self.ctx.breakpoint_sites();
        apply_breakpoint_updates(
            ids,
            breakpoints,
            &self.caches,
            "disabled",
            |breakpoints, id| breakpoints.disable(backend, target, id),
        )
    }

    fn cmd_be(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(ids) = self.selected_breakpoint_ids(&invocation, "be") else {
            return Ok(());
        };
        let (breakpoints, backend, target) = self.ctx.breakpoint_sites();
        apply_breakpoint_updates(
            ids,
            breakpoints,
            &self.caches,
            "enabled",
            |breakpoints, id| breakpoints.enable(backend, target, id),
        )
    }
    fn cmd_bpc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpc") else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            outln!("{}\n", command_help("bpc"));
            return Ok(());
        }
        let (condition, expr) = if text.eq_ignore_ascii_case("clear") {
            (None, None)
        } else {
            let expr = match compile_repl_condition(Some(&text), self.radix) {
                Ok(Some(expr)) => expr,
                Ok(None) => unreachable!(),
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            };
            (Some(text), Some(expr))
        };
        match self.ctx.breakpoints.set_condition(id, condition, expr) {
            Ok(()) => outln!("breakpoint {} condition updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, invocation.name) else {
            return Ok(());
        };
        let text = invocation.join_args(1);
        if text.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let action = (!text.eq_ignore_ascii_case("clear")).then_some(text);
        match self.ctx.breakpoints.set_action(id, action) {
            Ok(()) => outln!("breakpoint {} action updated\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bsc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bsc") else {
            return Ok(());
        };
        // A quoted last argument is the commands; everything between is the
        // condition, which may itself contain spaces.
        let rest = invocation.argv.get(1..).unwrap_or(&[]);
        let (condition_args, action) = match rest.split_last() {
            Some((Cow::Owned(commands), condition)) => (
                condition,
                Some(commands.clone()).filter(|text| !text.is_empty()),
            ),
            _ => (rest, None),
        };
        let condition = join_breakpoint_args(condition_args);
        if condition.is_empty() {
            outln!("{}\n", command_help("bsc"));
            return Ok(());
        }
        let expr = match compile_repl_condition(Some(&condition), self.radix) {
            Ok(expr) => expr,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let updated = self
            .ctx
            .breakpoints
            .set_condition(id, Some(condition), expr)
            .and_then(|()| self.ctx.breakpoints.set_action(id, action));
        match updated {
            Ok(()) => outln!(
                "breakpoint {} condition and commands updated\n",
                ui::bp_id(id)
            ),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_br(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(old_id) = Self::breakpoint_id_arg(&invocation, "br") else {
            return Ok(());
        };
        let Some(new_text) = invocation.arg(1) else {
            outln!("{}\n", command_help("br"));
            return Ok(());
        };
        let new_id = match new_text.parse::<u32>() {
            Ok(id) => id,
            Err(_) => {
                error!("invalid breakpoint ID: {new_text}");
                return Ok(());
            }
        };
        match self.ctx.breakpoints.renumber(old_id, new_id) {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                outln!(
                    "breakpoint {} renumbered to {}\n",
                    ui::bp_id(old_id),
                    ui::bp_id(new_id)
                );
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_bpp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bpp") else {
            return Ok(());
        };
        let Some(text) = invocation.arg(1) else {
            outln!("{}\n", command_help("bpp"));
            return Ok(());
        };
        let passes = match self.parse_radix_u64(text, "pass count") {
            Ok(passes) => passes,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.breakpoints.set_pass_count(id, passes) {
            Ok(()) => outln!("breakpoint {} pass count reset\n", ui::bp_id(id)),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_option_numbers_honor_radix_prefixes() {
        let pid = |text: &str, radix| {
            parse_breakpoint_arguments(
                &[
                    Cow::from("/p"),
                    Cow::from(text),
                    Cow::from("nt!NtCreateFile"),
                ],
                radix,
                "bp",
                false,
            )
            .map(|parsed| parsed.pid)
        };

        assert_eq!(pid("7772", NumberRadix::Hexadecimal).unwrap(), Some(7772));
        assert_eq!(pid("0n7952", NumberRadix::Hexadecimal).unwrap(), Some(7952));
        assert_eq!(pid("0x1f10", NumberRadix::Decimal).unwrap(), Some(0x1f10));
        assert_eq!(pid("7952", NumberRadix::Decimal).unwrap(), Some(7952));
        assert!(pid("notanumber", NumberRadix::Hexadecimal).is_err());
    }

    #[test]
    fn breakpoint_id_selectors_accept_lists_and_ranges() {
        assert_eq!(
            parse_breakpoint_id_selectors(&["0", "2", "5"]).unwrap(),
            BreakpointIdSelection::Ids(vec![0, 2, 5])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["1-3"]).unwrap(),
            BreakpointIdSelection::Ids(vec![1, 2, 3])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["1-3", "2", "5"]).unwrap(),
            BreakpointIdSelection::Ids(vec![1, 2, 3, 5])
        );
        assert_eq!(
            parse_breakpoint_id_selectors(&["*"]).unwrap(),
            BreakpointIdSelection::All
        );
    }

    #[test]
    fn bpcmds_lines_parse_back_to_the_same_breakpoint() {
        let full = ParsedBreakpointArgs {
            target: "0xfffff80000001000".to_string(),
            access_spec: Some("w4".to_string()),
            one_shot: true,
            // `ba` takes no `/a`.
            unchecked: false,
            pid: Some(7952),
            thread: Some(0xffffe0000badf00d),
            processor: Some(3),
            pass_count: 0x10,
            condition: Some("poi(@rcx + 8) == 0 and @rdx != 1".to_string()),
            action: Some(r#".printf "a\\b\n", @rcx; j (1) 'k' ; 'gc'"#.to_string()),
        };
        let bare = ParsedBreakpointArgs {
            target: "nt!NtClose".to_string(),
            access_spec: None,
            one_shot: false,
            unchecked: true,
            pid: None,
            thread: None,
            processor: None,
            pass_count: 0,
            condition: None,
            action: Some("gc".to_string()),
        };
        for (command, args) in [("ba", full), ("bu", bare)] {
            let line = breakpoint_command_line(command, &args);
            let parsed = parse_command(&line).unwrap().unwrap();
            assert_eq!(parsed.name, command);
            let invocation = parsed.invocation(CommandStyle::StructuredArgs).unwrap();
            let reparsed = parse_breakpoint_arguments(
                &invocation.argv,
                NumberRadix::Decimal,
                command,
                args.access_spec.is_some(),
            )
            .unwrap();
            assert_eq!(reparsed, args, "{line}");
            // The line is one command, whatever `;` its strings hold.
            assert_eq!(split_command_list(&line).unwrap(), vec![line.as_str()]);
        }
    }

    /// `.bpcmds` writes a hypercall breakpoint as the `!hvbp` line that sets
    /// the same filter, options, condition, and action, in any radix: the
    /// IDs are not taken for a pass count or a condition, and no pass count
    /// is written, which `!hvbp` would take for a condition.
    #[test]
    fn a_hypercall_breakpoint_bpcmds_line_sets_it_again() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(1, VirtAddr(0xffff_f847_98a8_68a0), true, None);
        let mut bp = manager.get(1).unwrap().clone();
        bp.hypercall = Some(HypercallFilter {
            code: 0x000b,
            partition: Some(0x17),
            vp: Some(3),
        });
        bp.processor = Some(2);
        bp.one_shot = true;
        bp.pass_count = 5;
        bp.condition = Some("@rdx != 0".to_string());
        bp.action = Some("r rcx; gc".to_string());
        let (command, args) = recreate_breakpoint(&bp).unwrap();
        let line = breakpoint_command_line(command, &args);
        let parsed = parse_command(&line).unwrap().unwrap();
        assert_eq!(parsed.name, "!hvbp");
        let invocation = parsed.invocation(CommandStyle::StructuredArgs).unwrap();
        for radix in [NumberRadix::Decimal, NumberRadix::Hexadecimal] {
            let reparsed = parse_hypercall_arguments(&invocation.argv, radix, "!hvbp").unwrap();
            assert_eq!(hypercall_code_text(&reparsed.call, radix).unwrap(), 0x000b);
            assert_eq!(
                reparsed,
                ParsedHypercallArgs {
                    call: reparsed.call.clone(),
                    partition: Some(0x17),
                    vp: Some(3),
                    one_shot: true,
                    processor: Some(2),
                    condition: bp.condition.clone(),
                    action: bp.action.clone(),
                },
                "{line}"
            );
        }
    }

    #[test]
    fn hvbp_takes_a_call_by_name_or_code_and_refuses_nt_filters() {
        let parse = |line: &[&str]| {
            let argv: Vec<Cow<'_, str>> = line.iter().map(|arg| Cow::from(*arg)).collect();
            parse_hypercall_arguments(&argv, NumberRadix::Hexadecimal, "!hvbp")
        };
        let any = parse(&["HvCallPostMessage", "if", "@rdx==0"]).unwrap();
        assert_eq!((any.partition, any.vp), (None, None));
        assert_eq!(any.condition.as_deref(), Some("@rdx==0"));
        assert_eq!(
            hypercall_code_text(&any.call, NumberRadix::Hexadecimal).unwrap(),
            0x005c
        );
        assert_eq!(
            hypercall_code_text("0n11", NumberRadix::Hexadecimal).unwrap(),
            0x000b
        );
        assert!(hypercall_code_text("0x10000", NumberRadix::Hexadecimal).is_err());
        assert!(hypercall_code_text("HvCallUnimplemented", NumberRadix::Hexadecimal).is_err());
        assert!(parse(&["/p", "4", "HvCallPostMessage"]).is_err());
        assert!(parse(&["/t", "4", "HvCallPostMessage"]).is_err());
    }
}
