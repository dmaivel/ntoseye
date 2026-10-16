//! Breakpoint commands: setting code, hardware and hypervisor breakpoints,
//! listing them, and changing or clearing them by ID. The SDK's form is the
//! live `Breakpoint` handles of `dbg.breakpoints`, whose data is the same
//! [`BreakpointInfo`] record `bl` lists.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::backend::dbg_backend::HwBreakpointAccess;
use crate::base::diagnostics;
use crate::base::error::{Error, Result};
use crate::hosts::ui;
use crate::nt::breakpoints::{
    BreakpointCommands, BreakpointConfig, BreakpointId, BreakpointInfo, BreakpointScope,
    BreakpointSpec, HypercallFilter, ThreadScope,
};
use crate::nt::expr::{Expr, NumberRadix, parse_number_literal_text};
use crate::nt::guest::hypercalls;
use crate::nt::guest::vm_exits::{self, ExitFilter};
use crate::nt::target::decimal_pid_literal;
use crate::session::Session;
use ntoseye_macros::{command, grammar};

use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::commands::thread::ThreadResolution;
use crate::hosts::repl::*;

/// What a breakpoint command set, as the REPL reports it.
pub enum BreakpointsSet {
    /// `bp`: a breakpoint at an address, and why ntoseye could not confirm
    /// that an instruction starts there.
    Address {
        breakpoint: BreakpointInfo,
        address: VirtAddr,
        warning: Option<String>,
    },
    /// `bu`: a symbolic breakpoint.
    Symbolic {
        breakpoint: BreakpointInfo,
        spec: String,
        warning: Option<String>,
    },
    /// `bp`/`bu` given `file:line`: a breakpoint on each address it has.
    Source {
        breakpoints: Vec<BreakpointInfo>,
        spec: String,
    },
    /// `bm`: how many matches it set, and those that failed.
    Pattern {
        count: usize,
        limited: bool,
        errors: Vec<String>,
        spec: String,
    },
    /// `ba`.
    Hardware {
        breakpoint: BreakpointInfo,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        condition: Option<String>,
    },
    /// `!hvbp` (`hypercall`) or `!hvexit` (`VM-exit`).
    Hypervisor {
        kind: &'static str,
        breakpoint: Option<BreakpointInfo>,
    },
}

/// What `bc`, `bd` or `be` did to each breakpoint it named: done, or why
/// not.
pub struct BreakpointUpdates {
    verb: &'static str,
    results: Vec<(u32, Option<String>)>,
}

/// The words of a breakpoint-setting line, with their quoting kept: a
/// quoted word is the command string.
fn breakpoint_words<'a>(cursor: &mut ArgCursor<'a>) -> Vec<Cow<'a, str>> {
    cursor.take_all(|_| true)
}

fn invalid(error: Error) -> ArgError {
    ArgError::Message(error.to_string())
}

/// `bp`, `bu` and `bm`'s line: a software breakpoint's options, target,
/// pass count, condition and commands.
#[grammar(
    usage = "[/1] [/a] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <{}> [passes] [if <expr>] [do <commands>]",
    complete = Expression
)]
fn code_breakpoint(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ParsedBreakpointArgs, ArgError> {
    cx.state
        .ctx
        .require_software_breakpoints()
        .map_err(invalid)?;
    let words = breakpoint_words(cursor);
    parse_breakpoint_arguments(&words, cx.state.radix, cx.name, false).map_err(invalid)
}

/// `bm`'s line: [`code_breakpoint`]'s, whose target is a symbol pattern
/// and which takes no /a.
#[grammar(
    usage = "[/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <symbol-pattern> [passes] [if <expr>] [do <commands>]",
    complete = Expression
)]
fn pattern_breakpoint(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ParsedBreakpointArgs, ArgError> {
    code_breakpoint(cx, cursor)
}

/// `ba`'s line: the options, access and size, target, pass count,
/// condition and commands.
#[grammar(
    usage = "[/1] [/p <pid>] [/t <tid|ethread>] [/c <processor>] [/w \"<expr>\"] <access><size> <address> [passes] [if <expr>] [do <commands>]",
    complete = [None, Expression]
)]
fn hardware_breakpoint(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ParsedBreakpointArgs, ArgError> {
    let words = breakpoint_words(cursor);
    parse_breakpoint_arguments(&words, cx.state.radix, cx.name, true).map_err(invalid)
}

/// `!hvbp`'s and `!hvexit`'s line.
#[grammar(
    usage = "[/1] [/c <processor>] [/w \"<expr>\"] <{}> [partition-id [vp-index]] [if <expr>] [do <commands>]",
    complete = None
)]
fn hypervisor_breakpoint(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ParsedHypercallArgs, ArgError> {
    let words = breakpoint_words(cursor);
    parse_hypercall_arguments(&words, cx.state.radix, cx.name).map_err(invalid)
}

/// `bc`/`bd`/`be`'s IDs: `id`, `first-last`, or `*`.
#[grammar(usage = "<id|id-id|*>...", complete = Breakpoint)]
fn breakpoint_ids(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<BreakpointIdSelection, ArgError> {
    let words = cursor.take_all(|_| true);
    let args = words.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    if args.is_empty() {
        return Err(ArgError::Missing);
    }
    parse_breakpoint_id_selectors(&args).map_err(invalid)
}

/// The rest of the line, which a command needs.
#[grammar(usage = "<{}|clear>", complete = Expression)]
fn required_rest(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    let text = cursor.rest();
    if text.is_empty() {
        Err(ArgError::Missing)
    } else {
        Ok(text)
    }
}

/// `bpp`'s pass count: a number in the current radix.
#[grammar(usage = "<{}>", complete = [None])]
fn pass_count(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    let text = cursor.word().ok_or(ArgError::Missing)?;
    parse_radix_u64_text(&text, cx.state.radix, "pass count").map_err(invalid)
}

/// `bsc`'s condition and commands: a quoted last word is the commands, and
/// everything before it the condition, which may contain spaces.
#[grammar(usage = "<condition> [\"commands\"]", complete = Expression)]
fn condition_and_commands(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<(String, Option<String>), ArgError> {
    let rest = cursor.take_all(|_| true);
    let (condition_args, action) = match rest.split_last() {
        Some((Cow::Owned(commands), condition)) => (
            condition,
            Some(commands.clone()).filter(|text| !text.is_empty()),
        ),
        _ => (&rest[..], None),
    };
    let condition = join_breakpoint_args(condition_args);
    if condition.is_empty() {
        return Err(ArgError::Missing);
    }
    Ok((condition, action))
}

/// Set a breakpoint.
///
/// The breakpoint replaces the first byte of the instruction at the address,
/// so an instruction must start there. ntoseye confirms one by the symbol at
/// the address, or by decoding from the start of the function around it, and
/// refuses an address inside an instruction. When nothing near the address
/// says where instructions start, or that code cannot be read, bp sets the
/// breakpoint and warns that it could not check. /a skips the check. A
/// file:line sets a source breakpoint, as bu does.
#[command(
    names = ["bp"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_breakpoint(
    state: &mut ReplState<'_>,
    #[arg(parse = code_breakpoint, name = "address|file:line")] args: ParsedBreakpointArgs,
) -> Result<BreakpointsSet> {
    let spec = args.target.clone();
    let config = state.breakpoint_config(args)?;
    let address = match Expr::eval_with_radix(&spec, &state.ctx.target, state.radix) {
        Ok(address) => address,
        Err(error) => match state.resolve_symbol_in_scope(&spec, config.scope.as_ref()) {
            Some(address) => address,
            // `bp queue.c:42` is a source line, which only fails as an
            // expression.
            None if BreakpointSpec::source(&spec, 0).is_some() => {
                return set_source_breakpoint(state.ctx, spec, config);
            }
            None => return Err(error),
        },
    };
    let set = state.ctx.set_code_breakpoint(address, config)?;
    Ok(BreakpointsSet::Address {
        breakpoint: added(state.ctx, set.id)?,
        address,
        warning: set.warning,
    })
}

/// Set a deferred symbolic breakpoint.
///
/// A symbol with an offset, such as mydriver!DriverEntry+0x20, must name the
/// start of an instruction, which ntoseye checks as bp does. Until the symbol
/// resolves nothing says where its instructions start, so bu sets the
/// breakpoint and warns that it could not check. /a skips the check. A
/// file:line sets a source breakpoint on each address the line has.
#[command(
    names = ["bu"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_symbolic_breakpoint(
    state: &mut ReplState<'_>,
    #[arg(parse = code_breakpoint, name = "symbol|file:line")] args: ParsedBreakpointArgs,
) -> Result<BreakpointsSet> {
    let spec = args.target.clone();
    let config = state.breakpoint_config(args)?;
    if BreakpointSpec::source(&spec, 0).is_some() {
        return set_source_breakpoint(state.ctx, spec, config);
    }
    let set = state.ctx.set_symbolic_breakpoint(spec.clone(), config)?;
    Ok(BreakpointsSet::Symbolic {
        breakpoint: added(state.ctx, set.id)?,
        spec,
        warning: set.warning,
    })
}

/// Set deferred symbolic breakpoints on the symbols that match a pattern.
///
/// Only code symbols match, so bm skips the data symbols that the pattern
/// also matches.
#[command(
    names = ["bm"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_pattern_breakpoints(
    state: &mut ReplState<'_>,
    #[arg(parse = pattern_breakpoint)] args: ParsedBreakpointArgs,
) -> Result<BreakpointsSet> {
    const BM_LIMIT: usize = 256;
    let spec = args.target.clone();
    let config = state.breakpoint_config(args)?;
    let set = state.ctx.add_pattern_breakpoints(&spec, config, BM_LIMIT)?;
    Ok(BreakpointsSet::Pattern {
        count: set.ids.len(),
        limited: set.limited,
        errors: set.errors.iter().map(ToString::to_string).collect(),
        spec,
    })
}

/// Set a hardware (debug-register) breakpoint.
///
/// The access is e=execute, r=read/write, or w=write, and the size is 1, 2,
/// 4, or 8 bytes. An execute breakpoint has size 1. The command is not
/// available on a dump or on the `memory` backend. Example: ba w4
/// nt!MyGlobal. In VTL1 (the .vtl 1 view or a vCPU stopped in VTL1), ntoseye
/// accepts only `ba e1`, and only on GDB backends. This breakpoint is global,
/// so you cannot use /p or /t, which name NT processes and threads. Example:
/// .vtl 1; ba e1 securekernel!SkeSelectProcessAddressSpace; g
#[command(
    names = ["ba"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_hardware_breakpoint(
    state: &mut ReplState<'_>,
    #[arg(parse = hardware_breakpoint)] args: ParsedBreakpointArgs,
) -> Result<BreakpointsSet> {
    let Some(spec) = args.access_spec.as_deref() else {
        return Err(Error::DebugInfo("ba: missing access/size".to_string()));
    };
    let (access, len) = parse_hw_breakpoint_spec(spec)?;
    let target = args.target.clone();
    let condition = args.condition.clone();
    let config = state.breakpoint_config(args)?;
    // A user-mode symbol under `/p` is the process's, as for `bp`.
    let address = match Expr::eval_with_radix(&target, &state.ctx.target, state.radix) {
        Ok(address) => address,
        Err(error) => state
            .resolve_symbol_in_scope(&target, config.scope.as_ref())
            .ok_or(error)?,
    };
    let id = state
        .ctx
        .set_hardware_breakpoint(address, access, len, config)?;
    Ok(BreakpointsSet::Hardware {
        breakpoint: added(state.ctx, id)?,
        address,
        access,
        len,
        condition,
    })
}

/// Set a breakpoint that stops on a hypercall to the Windows hypervisor, optionally only from one partition or VP.
///
/// Sets a hardware execute breakpoint on the hypercall's handler, which the
/// hypervisor's hypercall table gives (see !hvcalls), so it needs the gdb
/// backend and a free debug register. The call is a call code, in the current
/// radix, or its name: the TLFS name (HvCallPostMessage) or the name x hv!*
/// shows (HvCall0004). Many codes share a handler, HvCallUnimplemented's for
/// every code that is not implemented, so at each hit ntoseye reads the
/// caller's call code from its RCX and resumes the target without a stop
/// when it is another. The caller is the VP whose exit the processor handles:
/// the guest partition's VP it serves, or the root partition's VP. With a
/// partition ID, and a VP index in it, the breakpoint stops only for that
/// caller; the IDs use the current radix, and ntoseye refuses a partition or
/// VP that the hypervisor does not have. A hit whose caller ntoseye cannot
/// tell, or whose caller matches but whose registers it cannot read, stops,
/// so the filter does not hide a hit. /1, /c, /w, if, and do work as for ba;
/// a condition sees the caller's registers at its VMCALL (as !hvcall decodes
/// them), not the hypervisor's at the handler, and stops the hit with an
/// error when they are not known. The command takes no pass count: set it
/// with bpp. bl shows the filter. Needs the VM's hv-evmcs enlightenment.
/// Example: !hvbp HvCallSendSyntheticClusterIpi 3; g
#[command(
    names = ["!hvbp"],
    category = "breakpoints and events",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_hypercall_breakpoint(
    state: &mut ReplState<'_>,
    #[arg(parse = hypervisor_breakpoint, name = "code|name")] args: ParsedHypercallArgs,
) -> Result<BreakpointsSet> {
    let code = hypercall_code_text(&args.call, state.radix)?;
    let (vp, config) = state.hypervisor_breakpoint_config(&args)?;
    let id = state.ctx.add_hypercall_breakpoint(
        HypercallFilter {
            code,
            partition: args.partition,
            vp,
        },
        config,
    )?;
    Ok(BreakpointsSet::Hypervisor {
        kind: "hypercall",
        breakpoint: state.ctx.breakpoints.get(id).cloned(),
    })
}

/// Set a breakpoint that stops on a VM exit to the Windows hypervisor by its reason, optionally only from one partition or VP.
///
/// Sets a hardware execute breakpoint on the hypervisor's VM-exit entry point
/// (hv!VmExitEntry, the host RIP of every eVMCS), so it needs the gdb
/// backend, the VM's hv-evmcs enlightenment and a free debug register. The
/// reason is a basic exit reason (Intel SDM Appendix C), as a decimal or 0x
/// number, or a name as !hvvps shows it: cpuid, rdmsr, wrmsr, io_instruction,
/// ept_violation, vmcall, hlt. Every exit enters there, so at each hit
/// ntoseye reads the reason from the eVMCS the processor has loaded and
/// resumes the target without a stop when it is another; the guest runs far
/// slower while the breakpoint is set. With a guest partition's ID it rarely
/// stops: that partition's VPs run only when the root partition's NT runs
/// them, which it barely does then; !hvbp stops on a guest's hypercalls
/// without slowing the rest. The caller is the VP whose exit it is, as for
/// !hvbp: with a partition ID, and a VP index in it, the breakpoint stops
/// only for that caller. The condition is evaluated on the caller's registers
/// at its exit and reads the caller's memory. Example: !hvexit cpuid 6 if
/// @rax==0x40000000
#[command(
    names = ["!hvexit"],
    category = "breakpoints and events",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn set_exit_breakpoint(
    state: &mut ReplState<'_>,
    #[arg(parse = hypervisor_breakpoint, name = "reason")] args: ParsedHypercallArgs,
) -> Result<BreakpointsSet> {
    let reason = vm_exits::parse_reason(&args.call)?;
    let (vp, config) = state.hypervisor_breakpoint_config(&args)?;
    let id = state.ctx.add_exit_breakpoint(
        ExitFilter {
            reason,
            partition: args.partition,
            vp,
        },
        config,
    )?;
    Ok(BreakpointsSet::Hypervisor {
        kind: "VM-exit",
        breakpoint: state.ctx.breakpoints.get(id).cloned(),
    })
}

/// The breakpoint `id` a command just set.
fn added(session: &Session, id: u32) -> Result<BreakpointInfo> {
    session
        .breakpoints
        .get(id)
        .cloned()
        .ok_or(Error::BPNotFound(id))
}

/// Set a source breakpoint on each address `file:line` has (`bu` and `bp`
/// given a source line).
fn set_source_breakpoint(
    session: &mut Session,
    spec: String,
    config: BreakpointConfig,
) -> Result<BreakpointsSet> {
    let ids = session.add_source_breakpoint(spec.clone(), config)?;
    let breakpoints = ids
        .into_iter()
        .map(|id| added(session, id))
        .collect::<Result<_>>()?;
    Ok(BreakpointsSet::Source { breakpoints, spec })
}

impl Render for BreakpointsSet {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        repl.caches.refresh_breakpoints(&repl.ctx.breakpoints);
        match self {
            BreakpointsSet::Address {
                breakpoint,
                address,
                warning,
            } => {
                // Before the result, so the warning is not lost below it.
                if let Some(warning) = warning {
                    diagnostics::print_warning(warning);
                }
                outln!(
                    "breakpoint {} set at {}{}{}\n",
                    ui::bp_id(breakpoint.id),
                    ui::addr(address.0),
                    breakpoint
                        .symbol
                        .as_ref()
                        .map(|symbol| format!(" ({})", ui::symbol(symbol)))
                        .unwrap_or_default(),
                    format!(" ({})", breakpoint.scope_label()).bright_black(),
                );
                // The target accepted the site into its own table but its
                // page is out, so the opcode is owed. Say so rather than
                // letting the confirmation imply an armed site.
                if breakpoint.awaiting_page_in() {
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
            BreakpointsSet::Symbolic {
                breakpoint,
                spec,
                warning,
            } => {
                if let Some(warning) = warning {
                    diagnostics::print_warning(warning);
                }
                outln!("symbolic breakpoint {}\n", ui::bp_id(breakpoint.id));
                if breakpoint.deferred() {
                    outln!(
                        "  {} is deferred until '{}' resolves\n",
                        ui::bp_id(breakpoint.id),
                        spec
                    );
                }
            }
            BreakpointsSet::Source { breakpoints, spec } => match breakpoints.as_slice() {
                [breakpoint] if breakpoint.deferred() => outln!(
                    "source breakpoint {} deferred until '{}' resolves\n",
                    ui::bp_id(breakpoint.id),
                    spec
                ),
                [breakpoint] => outln!(
                    "source breakpoint {} set for '{}'\n",
                    ui::bp_id(breakpoint.id),
                    spec
                ),
                breakpoints => {
                    outln!(
                        "{} source breakpoints set for '{}'\n",
                        breakpoints.len(),
                        spec
                    )
                }
            },
            BreakpointsSet::Pattern {
                count,
                limited,
                errors,
                spec,
            } => {
                for error in errors {
                    error!("bm: {error}");
                }
                if *count == 0 {
                    outln!("no code symbols match '{}'\n", spec);
                } else {
                    let suffix = if *limited {
                        "; results limited to 256, refine the pattern"
                    } else {
                        ""
                    };
                    outln!("{} symbolic breakpoint(s) set{suffix}\n", count);
                }
            }
            BreakpointsSet::Hardware {
                breakpoint,
                address,
                access,
                len,
                condition,
            } => {
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                outln!(
                    "hardware breakpoint {} ({} {}b) set at {}{}{}\n",
                    ui::bp_id(breakpoint.id),
                    access.label(),
                    len,
                    ui::addr(address.0),
                    breakpoint
                        .symbol
                        .as_ref()
                        .map(|s| format!(" ({})", ui::symbol(s)))
                        .unwrap_or_default(),
                    condition_label.bright_black(),
                );
            }
            BreakpointsSet::Hypervisor { kind, breakpoint } => {
                if let Some(bp) = breakpoint {
                    outln!(
                        "{kind} breakpoint {} set at {}{}{}\n",
                        ui::bp_id(bp.id),
                        ui::addr(bp.address.0),
                        bp.symbol
                            .as_ref()
                            .map(|symbol| format!(" ({})", ui::symbol(symbol)))
                            .unwrap_or_default(),
                        format!(" ({})", bp.scope_label()).bright_black(),
                    );
                }
            }
        }
    }
}

/// List all breakpoints.
///
/// The status column shows `e` for enabled, `d` for disabled, or `o` for
/// owed. An owed breakpoint is a kernel code breakpoint that waits for its
/// page to become resident.
#[command(
    names = ["bl"],
    category = "breakpoints and events",
    kind = Query,
    python = Breakpoints,
    python_name = "list",
)]
fn list_breakpoints(session: &Session) -> Result<Vec<BreakpointInfo>> {
    Ok(session.breakpoints.list().into_iter().cloned().collect())
}

impl Render for Vec<BreakpointInfo> {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.is_empty() {
            outln!("no breakpoints set\n");
            return;
        }
        #[cfg(feature = "cli")]
        native::render(
            || native::lists::breakpoints(self),
            || print_breakpoint_list(self),
        );
        #[cfg(not(feature = "cli"))]
        print_breakpoint_list(self);
    }
}

/// Print the commands that set the current breakpoints again.
///
/// The output has one line for each breakpoint, in ID order. An address
/// breakpoint shows as `bp <address>`, a symbolic or source breakpoint as `bu
/// <symbol>` (as `bm` creates it), a hardware breakpoint as `ba
/// <access><size> <address>`, and a hypercall breakpoint as `!hvbp <code>
/// [partition-id [vp-index]]`, without its pass count, which !hvbp does not
/// take. Each line also has the /1, /p, /t, and /c options of the breakpoint,
/// its condition (as /w), its pass count, and its command string. To set the
/// same breakpoints again, run the lines, either by pasting them or by saving
/// them to a file for `$$<`. WinDbg puts a breakpoint ID in each line, but
/// these lines have none because the ntoseye bp command does not take one, so
/// the new breakpoints get new IDs. A disabled breakpoint comes back enabled.
#[command(
    names = [".bpcmds"],
    category = "breakpoints and events",
    kind = Query,
    python = Breakpoints,
    python_name = "commands",
)]
fn breakpoint_commands(session: &Session) -> Result<BreakpointCommands> {
    Ok(BreakpointCommands {
        commands: session
            .breakpoints
            .list()
            .into_iter()
            .filter_map(recreate_breakpoint)
            .map(|(command, args)| breakpoint_command_line(command, &args))
            .collect(),
    })
}

impl Render for BreakpointCommands {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for line in &self.commands {
            outln!("{line}");
        }
    }
}

/// Resume from the breakpoint that runs the current command string.
///
/// Use this command only in the command string of a breakpoint, where it
/// stops the command string and resumes the target. You can put it at the end
/// (`bp nt!NtClose "r rcx; gc"`) or in a branch (`bp nt!NtClose "j (@rcx ==
/// 0) '' ; 'gc'"`), and the commands after it do not run. A plain `g` in the
/// command string does the same, as in WinDbg scripts, but ntoseye does not
/// accept `g <address>` or other run control there.
#[command(
    names = ["gc"],
    category = "breakpoints and events",
    kind = Host,
    python = none,
)]
fn resume_from_action(state: &mut ReplState<'_>) -> Result<Flow> {
    if state.context != DispatchContext::BreakpointAction {
        error!("gc resumes only from a breakpoint's command string; use g");
        return Ok(Flow::Denied);
    }
    Ok(Flow::Jump(Jump::Resume))
}

/// The breakpoints `selection` names that exist, in its order.
fn managed(session: &Session, selection: BreakpointIdSelection) -> Vec<u32> {
    let managed = session.breakpoints.managed_ids();
    match selection {
        BreakpointIdSelection::All => managed,
        BreakpointIdSelection::Ids(ids) => {
            let managed: HashSet<u32> = managed.into_iter().collect();
            ids.into_iter().filter(|id| managed.contains(id)).collect()
        }
    }
}

/// Apply `update` to each breakpoint `selection` names, as `verb` says.
fn update_breakpoints(
    session: &mut Session,
    selection: BreakpointIdSelection,
    verb: &'static str,
    mut update: impl FnMut(&mut Session, u32) -> Result<()>,
) -> BreakpointUpdates {
    let results = managed(session, selection)
        .into_iter()
        .map(|id| (id, update(session, id).err().map(|error| error.to_string())))
        .collect();
    BreakpointUpdates { verb, results }
}

impl Render for BreakpointUpdates {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let mut changed = false;
        for (id, error) in &self.results {
            match error {
                None => {
                    changed = true;
                    outln!("breakpoint {} {}", ui::bp_id(*id), self.verb);
                }
                Some(error) => error!("{error}"),
            }
        }
        if changed {
            repl.caches.refresh_breakpoints(&repl.ctx.breakpoints);
            outln!();
        }
    }
}

/// Clear one or more breakpoints by ID.
#[command(
    names = ["bc"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn clear_breakpoints(
    session: &mut Session,
    #[arg(parse = breakpoint_ids)] ids: BreakpointIdSelection,
) -> Result<BreakpointUpdates> {
    Ok(update_breakpoints(
        session,
        ids,
        "cleared",
        |session, id| session.remove_breakpoint(id),
    ))
}

/// Disable one or more breakpoints by ID.
#[command(
    names = ["bd"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn disable_breakpoints(
    session: &mut Session,
    #[arg(parse = breakpoint_ids)] ids: BreakpointIdSelection,
) -> Result<BreakpointUpdates> {
    Ok(update_breakpoints(
        session,
        ids,
        "disabled",
        |session, id| session.disable_breakpoint(id),
    ))
}

/// Enable one or more breakpoints by ID.
#[command(
    names = ["be"],
    category = "breakpoints and events",
    kind = Action,
    state = Halted,
    writes = [Breakpoints],
    python = none,
)]
fn enable_breakpoints(
    session: &mut Session,
    #[arg(parse = breakpoint_ids)] ids: BreakpointIdSelection,
) -> Result<BreakpointUpdates> {
    Ok(update_breakpoints(
        session,
        ids,
        "enabled",
        |session, id| session.enable_breakpoint(id),
    ))
}

/// Change or clear a breakpoint condition.
#[command(
    names = ["bpc"],
    category = "breakpoints and events",
    kind = Action,
    writes = [Breakpoints],
    python = none,
)]
fn set_condition(
    state: &mut ReplState<'_>,
    id: BreakpointId,
    #[arg(parse = required_rest)] condition: String,
) -> Result<()> {
    let BreakpointId(id) = id;
    let (condition, expr) = if condition.eq_ignore_ascii_case("clear") {
        (None, None)
    } else {
        let expr = compile_repl_condition(Some(&condition), state.radix)?;
        (Some(condition), expr)
    };
    state.ctx.breakpoints.set_condition(id, condition, expr)?;
    outln!("breakpoint {} condition updated\n", ui::bp_id(id));
    Ok(())
}

/// Set the condition and the commands of a breakpoint together.
///
/// This is the WinDbg update-conditional-breakpoint command. The breakpoint
/// stops only when <condition> is nonzero, and then runs the quoted commands.
/// Use semicolons between the commands (`bsc 0 @rcx==4 "k; g"`). If you do not
/// give commands, bsc removes the current commands of the breakpoint.
#[command(
    names = ["bsc"],
    category = "breakpoints and events",
    kind = Action,
    writes = [Breakpoints],
    python = none,
)]
fn set_condition_and_commands(
    state: &mut ReplState<'_>,
    id: BreakpointId,
    #[arg(parse = condition_and_commands)] update: (String, Option<String>),
) -> Result<()> {
    let BreakpointId(id) = id;
    let (condition, action) = update;
    let expr = compile_repl_condition(Some(&condition), state.radix)?;
    let breakpoints = &mut state.ctx.breakpoints;
    breakpoints.set_condition(id, Some(condition), expr)?;
    breakpoints.set_action(id, action)?;
    outln!(
        "breakpoint {} condition and commands updated\n",
        ui::bp_id(id)
    );
    Ok(())
}

/// Set or clear the command action of a breakpoint.
#[command(
    names = ["bs", "bpa"],
    category = "breakpoints and events",
    kind = Action,
    writes = [Breakpoints],
    python = none,
)]
fn set_commands(
    session: &mut Session,
    id: BreakpointId,
    #[arg(parse = required_rest)] commands: String,
) -> Result<()> {
    let BreakpointId(id) = id;
    let action = (!commands.eq_ignore_ascii_case("clear")).then_some(commands);
    session.breakpoints.set_action(id, action)?;
    outln!("breakpoint {} action updated\n", ui::bp_id(id));
    Ok(())
}

/// Change the ID of a breakpoint.
#[command(
    names = ["br"],
    category = "breakpoints and events",
    kind = Action,
    writes = [Breakpoints],
    python = none,
)]
fn renumber_breakpoint(
    state: &mut ReplState<'_>,
    id: BreakpointId,
    new_id: BreakpointId,
) -> Result<()> {
    let (BreakpointId(old_id), BreakpointId(new_id)) = (id, new_id);
    state.ctx.breakpoints.renumber(old_id, new_id)?;
    state.caches.refresh_breakpoints(&state.ctx.breakpoints);
    outln!(
        "breakpoint {} renumbered to {}\n",
        ui::bp_id(old_id),
        ui::bp_id(new_id)
    );
    Ok(())
}

/// Reset the pass count of a breakpoint.
#[command(
    names = ["bpp"],
    category = "breakpoints and events",
    kind = Action,
    writes = [Breakpoints],
    python = none,
)]
fn reset_pass_count(
    session: &mut Session,
    id: BreakpointId,
    #[arg(parse = pass_count)] passes: u64,
) -> Result<()> {
    let BreakpointId(id) = id;
    session.breakpoints.set_pass_count(id, passes)?;
    outln!("breakpoint {} pass count reset\n", ui::bp_id(id));
    Ok(())
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
fn recreate_breakpoint(bp: &BreakpointInfo) -> Option<(&'static str, ParsedBreakpointArgs)> {
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
fn print_breakpoint_list(bps: &[BreakpointInfo]) {
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
            return Err(Error::InvalidArgument(usage_error(
                "ba",
                format!("missing size in '{spec}'"),
            )));
        }
        other => other.parse().map_err(|_| {
            Error::InvalidArgument(format!("invalid size '{other}' (use 1, 2, 4, or 8)"))
        })?,
    };
    Ok((access, len))
}

impl ReplState<'_> {
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
        let count = crate::nt::cpu_state::processor_count(&self.ctx.target)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::output::capture;
    use crate::nt::breakpoints::BreakpointManager;
    use crate::session::session_over_memory;

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

    /// `bp` and `bu` check their site in the session functions that the
    /// SDK's `breakpoints.add` calls too, so the SDK refuses an address
    /// inside an instruction exactly as `bp` does, and sets nothing there.
    #[test]
    fn bp_and_the_sdk_refuse_an_address_inside_an_instruction() {
        // driver!Function starts with `mov [rsp+8], rbx`, five bytes long.
        let mut code = [0x90u8; 0x40];
        code[0x10..0x15].copy_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x08]);
        let mut session = session_over_memory(0x1000, &code);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, Vec::new(), &[("Function", 0x10)]);
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x40,
            "driver.c",
            &[],
        );
        let inside = "is inside the instruction at driver!Function";

        let address = session
            .set_code_breakpoint(VirtAddr(0x1012), BreakpointConfig::default())
            .err()
            .expect("the SDK's address breakpoint is refused");
        assert!(address.to_string().contains(inside), "{address}");
        let symbolic = session
            .set_symbolic_breakpoint("driver!Function+2".into(), BreakpointConfig::default())
            .err()
            .expect("the SDK's symbolic breakpoint is refused");
        assert!(symbolic.to_string().contains(inside), "{symbolic}");

        let mut state = ReplState::for_oneshot(&mut session);
        for line in ["bp 0x1012", "bu driver!Function+2"] {
            let (_, text) = capture(|| state.dispatch_line(line));
            assert!(text.contains(inside), "{line}: {text}");
        }
        assert!(session.breakpoints.list().is_empty());
    }
}
