use std::collections::HashMap;

use crate::analysis::triage_report::user::exception_flag_names;
use crate::arch::{Arch, RegisterMap, ShownRegister};
use crate::backend::dbg_backend::processor_index_from_backend_thread_id;
use crate::base::diagnostics;
use crate::nt::bugchecks::{bugcheck_trap_frame_address, looks_like_kernel_pointer};
use ntoseye_macros::{command, grammar};

use crate::arch::arm64::unwind::Arm64UnwindCode;
use crate::arch::unwind::{Unwind, UnwindHandler};
use crate::base::error::{Error, Result};
use crate::base::ntstatus::ntstatus_name;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, virtual_memory};
use crate::hosts::repl::*;
use crate::nt::expr::{Expr, NumberRadix};
use crate::nt::target::{MemoryKind, SavedThreadRegisters, SelectedFrame, lookup_register};
use crate::nt::trapframe::{KtrapFrame, read_ktrap_frame_at_or_current, trap_frame_rip_symbol};
use crate::nt::unwind::{
    FrameSource, FunctionEntry, RecoveredStackTrace, StackTrace, UNKNOWN_CONTEXT,
    build_thread_stacktrace, halted_in_windows_hypervisor, resolve_thread_trace_context,
    saved_vtls, try_format_symbol,
};
use crate::session::effects::{Effects, Writes};
use crate::session::{ExceptionRecord, Session};

const MAX_FRAME_INDEX: usize = 4095;

/// The registers `r` names, `rcx, rdx` or `rcx rdx`, as the register map
/// spells them: no `@`, lowercase, and `efl`/`rflags` as `eflags`.
fn register_list(tail: &str) -> Vec<String> {
    tail.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|name| !name.is_empty())
        .map(
            |name| match name.trim_start_matches('@').to_ascii_lowercase().as_str() {
                "efl" | "rflags" => "eflags".to_string(),
                name => name.to_string(),
            },
        )
        .collect()
}

/// The value of the pseudo-register `name` (`$proc`, `$peb`, `$ra`, ...),
/// which `r` shows as WinDbg does, read the way an expression reads it.
fn pseudo_register_value(state: &ReplState<'_>, name: &str) -> Result<u64> {
    Expr::eval_with_radix(&format!("@{name}"), &state.ctx.target, state.ctx.radix)
        .map(|value| value.0)
}

/// A recovered trace, the registers its walk was seeded from, and whether
/// that seed is the live vCPU file (a `.cxr`/`.trap` context is not).
type SeededTrace = (RecoveredStackTrace, HashMap<String, u64>, bool);

/// A selected frame's call site, resolved once for both renderers.
pub struct FrameLine {
    pub symbol: String,
    /// `file:line` of the source line, when known.
    pub location: Option<String>,
    pub inline: bool,
}

/// The `.frame` text: the frame row, its frame base, and with
/// `show_registers` the frame's registers.
fn print_frame_line(line: &FrameLine, frame: &SelectedFrame, arch: Arch, show_registers: bool) {
    let tag = if line.inline {
        format!("  {}", inline_tag())
    } else {
        String::new()
    };
    let location = line
        .location
        .as_ref()
        .map(|location| format!("  [{location}]"))
        .unwrap_or_default();
    // The frame row as `k` lists it: the number, the child SP and the
    // instruction address, then the call site, in `k`'s columns.
    outln!(
        " {:02} {}  {}  {}{tag}{location}",
        frame.index,
        ui::addr(frame.sp),
        ui::addr(frame.ip),
        ui::symbol(&line.symbol),
    );
    if let Some(base) = frame.frame_base {
        outln!("  frame base {}", ui::addr(base));
    }
    if show_registers {
        print_known_registers(&frame.registers, arch, "registers");
    }
}

/// What a selection's registers are of, for `r`'s heading and errors: a
/// frame of a stack walk (`frame 1`), or a context read whole from memory
/// or a dump (`.cxr`, `.ecxr`, `.trap`), which no walk recovered.
fn selection_name(frame: &SelectedFrame) -> String {
    // Only a context selected from its registers alone has no address
    // space of a walk behind it.
    if frame.dtb.is_none() {
        "the selected context".to_string()
    } else {
        format!("frame {}", frame.index)
    }
}

/// Select or show a stack frame.
///
/// N is a zero-based frame number that counts inline frames, as k does, and
/// is decimal as k prints it, whatever the radix. /r
/// also shows the recovered registers of the frame. When you select an inline
/// frame, dv, ls, lsa, and local names in expressions use the function that
/// the compiler inlined there, and the registers are those of the frame that
/// contains it.
#[command(
    names = [".frame", "frame"],
    category = "execution and stack",
    kind = Action,
    state = HaltedOrParkedThread,
    python = none,
)]
fn frame(
    state: &mut ReplState<'_>,
    #[arg(parse = frame_request)] request: FrameRequest,
) -> Result<()> {
    let FrameRequest {
        show_registers,
        index,
    } = request;

    let Some(index) = index else {
        if let Some(frame) = state.ctx.target.selected_frame.as_ref() {
            state.show_selected_frame(frame, show_registers);
            return Ok(());
        }
        let Some((recovered, seed, live)) = state.recovered_trace(1)? else {
            return Ok(());
        };
        let Some(selected) = SelectedFrame::from_recovered(&recovered, 0, Some(&seed), live) else {
            error!("current frame is unavailable");
            return Ok(());
        };
        state.show_selected_frame(&selected, show_registers);
        return Ok(());
    };
    if index > MAX_FRAME_INDEX {
        error!("frame index is too large");
        return Ok(());
    }

    let limit = index.saturating_add(1);
    let Some((recovered, seed, live)) = state.recovered_trace(limit)? else {
        return Ok(());
    };
    let Some(selected) = SelectedFrame::from_recovered(&recovered, index, Some(&seed), live) else {
        error!("frame {} is unavailable", index);
        return Ok(());
    };
    state.set_selected_frame(selected.clone());
    state.show_selected_frame(&selected, show_registers);
    Ok(())
}

/// `.frame`'s words: `/r` (or `-r`) anywhere and one frame number; any
/// other word prints the help.
pub struct FrameRequest {
    show_registers: bool,
    index: Option<usize>,
}

#[grammar(usage = "[/r] [frame-number]", complete = Expression)]
fn frame_request(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<FrameRequest, ArgError> {
    let mut request = FrameRequest {
        show_registers: false,
        index: None,
    };
    while let Some(word) = cursor.word() {
        match word.as_ref() {
            "/r" | "-r" => request.show_registers = true,
            value if request.index.is_none() => {
                // `k` numbers frames in decimal, so `.frame` reads the
                // number it prints in decimal whatever the radix; `0x`
                // still names a hex number.
                let parsed =
                    Expr::eval_with_radix(value, &cx.state.ctx.target, NumberRadix::Decimal)
                        .map_err(|error| ArgError::Message(error.to_string()))?;
                request.index = Some(usize::try_from(parsed.0).unwrap_or(usize::MAX));
            }
            _ => return Err(ArgError::Missing),
        }
    }
    Ok(request)
}

/// Show the function table entry and unwind info of the function that
/// contains an address.
///
/// Shows the RUNTIME_FUNCTION that covers the address (the begin, end, and
/// unwind info RVAs), then its unwind data. On AMD64, the unwind data is the
/// UNWIND_INFO version, flags, prolog size, frame register, and frame offset,
/// each unwind code with its operands, and the exception or termination
/// handler. After a chained entry, .fnent shows the entry of each parent. On
/// ARM64, it shows the fields of packed unwind data (flag, RegF, RegI, H, CR,
/// frame size) and the prolog codes that they represent. For an .xdata
/// record, it shows the header, the epilog scopes, each unwind code with the
/// instruction that it undoes, and the exception handler. If a function table
/// is paged out, .fnent reads it from the image file on disk.
#[command(
    names = [".fnent"],
    category = "execution and stack",
    kind = Query,
    python = Memory,
    python_name = "function_entry",
)]
fn fnent(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    address: VirtAddr,
) -> Result<FunctionEntry> {
    memory.require_virtual()?;
    session.function_entry(address)
}

impl Render for FunctionEntry {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_function_entry(self);
    }
}

/// Select a CONTEXT record, or reset the selected context.
///
/// Without an address, .cxr goes back to the vCPU's own registers. At a stop
/// in the Windows hypervisor, these are the registers of the hypervisor,
/// which do not show where NT left off.
#[command(
    names = [".cxr"],
    category = "execution and stack",
    kind = Action,
    target = Nt,
    state = Halted,
    python = none,
)]
fn cxr(
    state: &mut ReplState<'_>,
    #[arg(parse = lone_address)] address: Option<VirtAddr>,
) -> Result<()> {
    let Some(address) = address else {
        report_context_reset(state);
        return Ok(());
    };
    let registers = match state.ctx.read_context_record(address) {
        Ok(registers) => registers,
        Err(error) => {
            error!("could not read a CONTEXT at {:#x}: {error}", address.0);
            return Ok(());
        }
    };
    let selected = SelectedFrame::from_registers(state.ctx.target.arch(), 0, registers);
    state.set_selected_frame(selected.clone());
    outln!("selected the CONTEXT at {:#x}", address.0);
    state.print_selected_frame(&selected, false);
    Ok(())
}

/// `.cxr` or `.trap` with nothing to select: go back to the processor's own
/// registers, and say so only when a context was selected.
fn report_context_reset(state: &mut ReplState<'_>) {
    if state.ctx.target.selected_frame.is_none() {
        outln!("no context is selected");
        return;
    }
    state.ctx.clear_selected_frame();
    outln!(
        "selected context cleared; registers are {}'s own",
        ui::thread(&state.ctx.current_thread)
    );
}

/// One optional expression; a second word prints the help.
#[grammar(usage = "[{}]", complete = Expression)]
fn lone_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    if cursor.remaining() > 1 {
        return Err(ArgError::Missing);
    }
    cursor.word().map(|word| cx.eval(&word)).transpose()
}

/// Select the current exception context.
#[command(
    names = [".ecxr"],
    category = "execution and stack",
    kind = Action,
    target = Nt,
    state = Halted,
    python = none,
)]
fn ecxr(state: &mut ReplState<'_>) -> Result<()> {
    // A user dump stores the exception's CONTEXT in its ExceptionStream.
    if state.ctx.target.user_dump().is_some() {
        match state.ctx.select_user_exception_context() {
            Ok((selected, thread)) => {
                state.caches.refresh_symbol_context(&state.ctx.target);
                outln!("exception context of thread {}", ui::thread_id(&thread));
                state.print_selected_frame(&selected, false);
            }
            Err(error) => error!("{error}"),
        }
        return Ok(());
    }
    if let Some(info) = state
        .ctx
        .last_event
        .as_ref()
        .and_then(|event| event.stop.bugcheck.as_ref())
        && matches!(info.code, 0x8e | 0x1000_008e)
    {
        let Some(address) = bugcheck_trap_frame_address(state.ctx.target.arch(), info) else {
            error!("no trap frame is available for the current bugcheck");
            return Ok(());
        };
        match read_ktrap_frame_at_or_current(&state.ctx.target, Some(VirtAddr(address))) {
            Ok(frame) => {
                let registers = registers_from_trap_frame(&frame);
                let selected = SelectedFrame::from_registers(state.ctx.target.arch(), 0, registers);
                state.set_selected_frame(selected.clone());
                outln!("selected the exception's trap frame at {address:#x}");
                state.print_selected_frame(&selected, false);
            }
            Err(error) => {
                error!("could not read the exception's trap frame at {address:#x}: {error}");
            }
        }
        return Ok(());
    }

    if let Some(address) = state.exception_context_pointer() {
        match state.ctx.read_context_record(VirtAddr(address)) {
            Ok(registers) => {
                let selected = SelectedFrame::from_registers(state.ctx.target.arch(), 0, registers);
                state.set_selected_frame(selected.clone());
                outln!("selected the exception's CONTEXT at {address:#x}");
                state.print_selected_frame(&selected, false);
            }
            Err(error) => {
                error!("could not read the exception's CONTEXT at {address:#x}: {error}")
            }
        }
        return Ok(());
    }

    // KD exception stops expose the exception context as the current
    // backend register file. Do not use this for a bugcheck stop: that
    // context is normally KeBugCheck rather than the faulting exception.
    let is_bugcheck = state
        .ctx
        .last_event
        .as_ref()
        .is_some_and(|event| event.stop.is_bugcheck);
    if !is_bugcheck {
        let Some(registers) = state.live_register_values() else {
            error!("exception context is unavailable");
            return Ok(());
        };
        let selected = SelectedFrame::from_registers(state.ctx.target.arch(), 0, registers);
        state.set_selected_frame(selected.clone());
        outln!("exception context from current stop");
        state.print_selected_frame(&selected, false);
        return Ok(());
    }

    error!("no exception context is available for the current bugcheck");
    Ok(())
}

/// Select the VTL0 or VTL1 context that the Windows hypervisor saved for a
/// vCPU halted in the hypervisor.
///
/// Use this command for a vCPU that stopped in the Windows hypervisor (VBS).
/// It reads the saved state of each VTL of the virtual processor from the
/// Enlightened VMCS page of that VTL, lists these states, and selects the
/// VTL0 state, so that r, k, and u show where NT left off. The VM must expose
/// hv-evmcs, and at the first use in each boot, the command scans host RAM
/// for the pages. The context has RIP, RSP, flags, control registers, and
/// segment registers from the Enlightened VMCS. For the current VTL it also
/// has the other general-purpose registers, read where the hypervisor's
/// VM-exit entry code saved them (experimental), and the command says why
/// when they are missing. .vtlcxr 1 selects the saved VTL1 state instead, in
/// the secure kernel's address space with its symbols, which it loads first
/// as .vtl 1 does: k walks the secure kernel's stack from where VTL1 left
/// off, usually its VTL return, and the context is read-only, as at a VTL1
/// stop: .vtlcxr goes back to the VTL0 state. Its general-purpose registers
/// are known only when VTL1 made the hypervisor's last exit. A stop in the
/// hypervisor selects the VTL0 state automatically. .cxr goes back to the
/// registers of the hypervisor, and .vtlcxr then selects the VTL0 state
/// again. See 'Where NT left off under the hypervisor' in the VBS guide.
#[command(
    names = [".vtlcxr"],
    category = "execution and stack",
    kind = Action,
    target = Machine,
    state = Halted,
    python = none,
)]
fn vtlcxr(state: &mut ReplState<'_>, #[arg(parse = vtl_choice)] vtl: u8) -> Result<()> {
    if let Err(error) = state
        .ctx
        .backend
        .set_current_thread(&state.ctx.current_thread)
    {
        error!("failed to select execution context: {error}");
        return Ok(());
    }
    let regs = match state.ctx.read_registers() {
        Ok(regs) => regs,
        Err(error) => {
            error!("failed to read registers: {error}");
            return Ok(());
        }
    };
    let target = &state.ctx.target;
    let map = &state.ctx.register_map;
    let (Ok(cr3), Ok(rip)) = (
        map.read_u64(target.arch().dtb_register(), &regs),
        map.read_u64(target.arch().pc_register(), &regs),
    ) else {
        error!("the vCPU's CR3 and RIP are unavailable");
        return Ok(());
    };
    if !halted_in_windows_hypervisor(target, cr3, rip) {
        error!(
            "{} is not halted in the Windows hypervisor",
            ui::thread(&state.ctx.current_thread)
        );
        return Ok(());
    }
    let processor = processor_index_from_backend_thread_id(&state.ctx.current_thread);
    let saved = match saved_vtls(target, cr3, rip, processor) {
        Ok(saved) => saved,
        Err(error) => {
            error!("{error}");
            return Ok(());
        }
    };
    if target.evmcs_found() == Some(false) {
        error!(
            "no Enlightened VMCS in guest RAM: the VM must expose hv-evmcs (libvirt <evmcs state=\"on\"/>) for the Windows hypervisor to use one"
        );
        return Ok(());
    }
    for vtl in &saved {
        let state = &vtl.context.state;
        let exit = state
            .exit_reason_name()
            .map_or_else(|| format!("exit {:#x}", state.exit_reason), str::to_string);
        outln!(
            "{}  rsp {}  last exit: {}{}",
            ui::symbol(&vtl.describe()),
            ui::addr(state.rsp),
            exit,
            if state.current {
                ui::muted("  (current)")
            } else {
                String::new()
            }
        );
        // The hypercall below its exit, as the line is long already.
        if let Some(detail) = vtl.context.exit_detail() {
            print_event_children("", &[detail]);
        }
    }
    let served = processor.and_then(|number| target.served_guest_vp(cr3, rip, number));
    if let Some(served) = &served {
        outln!(
            "{}{}",
            ui::symbol(&format!(
                "serving {}  {}",
                served.label(),
                served.left_off()
            )),
            if served.state.is_some_and(|state| state.current) {
                ui::muted("  (current)")
            } else {
                String::new()
            }
        );
        if let Some(detail) = served.exit_detail() {
            print_event_children("", &[detail]);
        }
    }
    let Some(chosen) = saved.iter().find(|saved| saved.context.vtl == vtl) else {
        error!("no saved VTL{vtl} state belongs to this vCPU's virtual processor");
        return Ok(());
    };
    // VTL1's state is read, as a live VTL1 stop's is, through its own
    // root, which the secure kernel's modules and symbols serve.
    if vtl == 1
        && let Err(error) = state.ctx.target.load_secure_kernel_symbols()
    {
        error!("the secure kernel's symbols: {error}");
    }
    let selected =
        SelectedFrame::from_registers(state.ctx.target.arch(), 0, chosen.context.registers());
    state.set_selected_frame(selected.clone());
    if vtl == 1 {
        state.caches.refresh_symbol_context(&state.ctx.target);
        outln!("selected the VTL1 context the hypervisor saved (read-only)");
    } else {
        outln!("selected the VTL0 context the hypervisor saved");
    }
    if let Err(reason) = &chosen.context.general_registers {
        let reason = match &served {
            Some(served) if served.state.is_some_and(|state| state.current) => {
                format!("the processor last ran {}", served.label())
            }
            _ => reason.clone(),
        };
        outln!(
            "{}",
            ui::muted(&format!(
                "general-purpose registers other than rsp: unknown ({reason})"
            ))
        );
    }
    if chosen.context.may_be_stale {
        outln!(
            "{}",
            ui::muted(
                "this vCPU is on the hypervisor's VM-exit entry, where the saved state may \
                 still describe the previous exit; the guest's general-purpose registers are \
                 the vCPU's own (.cxr)"
            )
        );
    }
    state.print_selected_frame(&selected, false);
    Ok(())
}

/// `.vtlcxr`'s VTL: none (0), `0` or `1`; anything else prints the help.
#[grammar(usage = "[0|1]")]
fn vtl_choice(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u8, ArgError> {
    let vtl = match (cursor.peek(), cursor.remaining()) {
        (None, _) | (Some("0"), 1) => 0,
        (Some("1"), 1) => 1,
        _ => return Err(ArgError::Missing),
    };
    cursor.word();
    Ok(vtl)
}

/// Show an EXCEPTION_RECORD64.
#[command(
    names = [".exr"],
    category = "execution and stack",
    kind = Query,
    target = Nt,
    python = Inspect,
    python_name = "exception_record",
)]
fn exr(
    session: &Session,
    #[arg(parse = exception_record_address, positional)] address: Option<VirtAddr>,
) -> Result<ExceptionRecord> {
    match address {
        Some(address) => session.read_exception_record(address).map_err(|error| {
            Error::DebugInfo(format!(
                "could not read an EXCEPTION_RECORD64 at {:#x}: {error}",
                address.0
            ))
        }),
        None => session
            .current_exception_record()
            .ok_or_else(|| Error::DebugInfo("no current exception record".to_string())),
    }
}

/// `.exr`'s record: an address, or `-1` (`None`) for the current
/// exception's. A missing or second word prints the help.
#[grammar(usage = "<{}|-1>", complete = Expression)]
fn exception_record_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    if cursor.remaining() != 1 {
        return Err(ArgError::Missing);
    }
    match cursor.word().as_deref() {
        Some("-1") => Ok(None),
        Some(text) => cx.eval(text).map(Some),
        None => Err(ArgError::Missing),
    }
}

impl Render for ExceptionRecord {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_exception_record(self);
    }
}

/// Show the CPU registers, or set the value of one register.
///
/// As in WinDbg, r rcx, rdx, r8 shows several registers on one line. r shows
/// a 128-bit register (xmm0, ARM64 v0) at full width, and you set it through
/// its 64-bit halves (xmm0l/xmm0h, v0l/v0h). For a vCPU stopped in VTL1, r
/// shows the VTL1 registers as read-only. The .vtl 1 memory view has no
/// registers.
#[command(
    names = ["r", "registers"],
    category = "execution and stack",
    kind = Query,
    state = HaltedOrParkedThread,
    python = none,
)]
fn registers(
    state: &mut ReplState<'_>,
    #[arg(invoked)] invoked: &str,
    #[arg(raw, usage = "[register[,register]...] | <register>=<expression>", complete = None)] tail: String,
) -> Result<()> {
    // A live frame 0 (`.frame 0`, or the frame an editor client keeps
    // selected) is the vCPU's own register file. Only a recovered context
    // is shown from its snapshot and refused assignment.
    if let Some(frame) = state
        .ctx
        .target
        .selected_frame
        .as_ref()
        .filter(|frame| !frame.is_live())
    {
        let tail = tail.trim();
        if tail.contains('=') {
            error!(
                "cannot assign registers while frame {} is selected; use `.cxr`/`.frame` reset first",
                frame.index
            );
            return Ok(());
        }
        let source = selection_name(frame);
        if !tail.is_empty() {
            // Named registers print as plain `r rip` prints them, with no
            // heading; one the selection lacks is named in the error.
            let mut shown = Vec::new();
            let arch = state.ctx.target.arch();
            for name in register_list(tail) {
                // A part of a register, or its other name, names one too.
                let known = state.ctx.register_map.contains(&name)
                    || arch.subregister(&name).is_some()
                    || arch.other_register_name(&name).is_some();
                match lookup_register(arch, &frame.registers, &name) {
                    Some(value) => shown.push(format!("{name}={}", ui::addr(value))),
                    None if known => error!("register '{name}' not recovered in {source}"),
                    None => error!("register '{name}' not found"),
                }
            }
            if !shown.is_empty() {
                outln!("{}", shown.join("  "));
            }
        } else {
            print_known_registers(
                &frame.registers,
                state.ctx.target.arch(),
                &format!("registers ({})", source.trim_start_matches("the ")),
            );
        }
        return Ok(());
    }
    if state.ctx.parked_windows_thread().is_some() {
        error!(
            "selected Windows thread is parked and has no coherent register context; use `vcpu <id>`"
        );
        return Ok(());
    }
    // A VTL1 stop is observed, never altered: the vCPU resumes VTL1 code
    // exactly as it was trapped.
    if state.ctx.target.in_secure_address_space() && tail.contains('=') {
        error!("VTL1 registers are read-only; the vCPU is stopped in VTL1");
        return Ok(());
    }
    if let Err(e) = state
        .ctx
        .backend
        .set_current_thread(&state.ctx.current_thread)
    {
        error!("failed to select execution context: {e}");
        return Ok(());
    }

    let mut regs = match state.ctx.read_registers() {
        Ok(r) => r,
        Err(e) => {
            error!("failed to read registers: {e}");
            return Ok(());
        }
    };
    state.ctx.target.registers = Some(
        state
            .ctx
            .target
            .register_values(&state.ctx.register_map, &regs),
    );

    if !tail.trim().is_empty() {
        let tail = tail.trim();
        let Some((name, expression)) = tail.split_once('=') else {
            let mut shown = Vec::new();
            for name in register_list(tail) {
                if name.starts_with('$') {
                    match pseudo_register_value(state, &name) {
                        Ok(value) => shown.push(format!("{name}={}", ui::addr(value))),
                        Err(e) => error!("{e}"),
                    }
                    continue;
                }
                match state.ctx.register_map.read_u64(&name, &regs) {
                    Ok(value) => shown.push(format!("{name}={}", ui::addr(value))),
                    Err(Error::RegisterTooWide(_)) => {
                        match state.ctx.register_map.read_u128(&name, &regs) {
                            Ok(value) => shown.push(format!("{name}={value:032x}")),
                            Err(e) => error!("{e}"),
                        }
                    }
                    Err(e) => error!("{e}"),
                }
            }
            if !shown.is_empty() {
                outln!("{}", shown.join("  "));
            }
            return Ok(());
        };
        let requested_name = name.trim().trim_start_matches('@').to_ascii_lowercase();
        let name = match requested_name.as_str() {
            "efl" | "rflags" => "eflags",
            name => name,
        };
        let expression = expression.trim();
        if name.is_empty() || expression.is_empty() {
            ArgError::Missing.report(invoked);
            return Ok(());
        }
        // Reading is this command's effect; setting a register is a write,
        // which the `.vtl 1` view refuses.
        if let Err(refusal) = state.ctx.admit(&Effects {
            writes: &[Writes::Registers],
            ..Effects::NONE
        }) {
            report_refusal(invoked, refusal);
            return Ok(());
        }
        let Some(VirtAddr(value)) = state.eval_or_report(expression) else {
            return Ok(());
        };
        if let Err(e) = state.ctx.write_register(name, value) {
            error!("failed to write register {name}: {e}");
            return Ok(());
        }
        regs = match state.ctx.read_registers() {
            Ok(regs) => regs,
            Err(e) => {
                error!("register written, but refresh failed: {e}");
                return Ok(());
            }
        };
        state.ctx.target.registers = Some(state.ctx.register_map.to_hashmap(&regs));
        outln!("@{name} = {}\n", ui::addr(value));
    }

    let register_map = &state.ctx.register_map;
    let arch = state.ctx.target.arch();
    // A user dump's contexts record no control registers.
    let control = state.ctx.target.user_dump().is_none();
    print_register_grid(register_map, &regs, arch, control);

    Ok(())
}

/// Show a stack.
///
/// kp adds the PDB parameter locations, kv adds the provenance of each frame,
/// and kf adds the frame sizes. A call that the compiler inlined is a
/// separate frame with the tag [inline], which is above the frame that
/// contains it and shows the addresses of that frame. The inline frame has
/// the name of the inlined function and shows the source line in that
/// function, and its caller shows the line of the call. Frame numbers include
/// inline frames, in decimal. After .frame, k lists the same stack and marks
/// the selected frame with *. In kf output, the column after the frame number is the
/// stack memory between the frame and the physical frame before it, in hex.
/// This column is blank for the first frame, for inline frames, and where the
/// walk moves to a different stack.
#[command(
    names = ["kn", "k", "kb", "kp", "kv", "kf"],
    category = "execution and stack",
    kind = Query,
    state = HaltedOrParkedThread,
    python = none,
)]
fn stack(
    state: &mut ReplState<'_>,
    #[arg(invoked)] name: &str,
    #[arg(default = 64)] count: u64,
) -> Result<()> {
    let columns = StackColumns {
        provenance: name.eq_ignore_ascii_case("kv"),
        frame_size: name.eq_ignore_ascii_case("kf"),
    };
    let frame_limit = usize::try_from(count).unwrap_or(usize::MAX).min(4096);
    if state.ctx.parked_windows_thread().is_some() && state.ctx.target.selected_frame.is_none() {
        let trace = match state.ctx.backtrace(frame_limit) {
            Ok(trace) => trace,
            Err(error) => {
                // The walk's error says the stack is unavailable and why.
                error!("{error}");
                return Ok(());
            }
        };
        print_stacktrace_data_with(state.ctx.target.arch(), &trace, frame_limit, false, columns);
        if name.eq_ignore_ascii_case("kp") {
            state.print_stack_parameters(&trace)?;
        }
        return Ok(());
    }

    let trace = if state.ctx.target.selected_frame.is_some() {
        // A selected frame's stack is the walk it came from, with the frame
        // marked, not a new walk from the frame's registers: those hold a
        // return address, which a walk would take for an exact pc and
        // resolve to the wrong line and inline frames.
        match state.ctx.recovered_backtrace(frame_limit) {
            Ok((trace, _, _)) => trace,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        }
    } else {
        if let Err(e) = state
            .ctx
            .backend
            .set_current_thread(&state.ctx.current_thread)
        {
            error!("failed to select execution context: {e}");
            return Ok(());
        }
        let regs = match state.ctx.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {e}");
                return Ok(());
            }
        };
        // A dump records a processor it captured no context for with every
        // register zero, as `~` lists it: a walk from there would invent a
        // frame at address 0.
        let pc = state
            .ctx
            .register_map
            .read_u64(state.ctx.target.arch().pc_register(), &regs);
        if matches!(pc, Ok(0)) {
            outln!(
                "{}",
                ui::muted(&format!(
                    "no register context for {}: the dump captured none for it",
                    ui::thread(&state.ctx.current_thread)
                ))
            );
            return Ok(());
        }
        build_thread_stacktrace(
            &state.ctx.target,
            &state.ctx.register_map,
            &regs,
            state.ctx.target.windows_thread_selection.as_ref(),
            frame_limit,
        )
    };
    let selected = state
        .ctx
        .target
        .selected_frame
        .as_ref()
        .map(|frame| frame.index);
    if !trace.frames.is_empty() {
        print_stack_header(columns);
    }
    print_indexed_stacktrace(
        state.ctx.target.arch(),
        &trace,
        frame_limit,
        columns,
        selected,
    );
    if !name.eq_ignore_ascii_case("kp") {
        return Ok(());
    }
    let plain = StackTrace {
        frames: trace
            .frames
            .iter()
            .map(|frame| frame.frame.clone())
            .collect(),
        truncated: trace.truncated,
    };
    state.print_stack_parameters(&plain)?;

    Ok(())
}

/// Show raw stack words from the stack pointer, with the symbol of each value
/// that resolves to one.
///
/// kd is the same as `dps @$csp L<count>` and shows one pointer-sized word on
/// each line, starting at the stack pointer of the selected frame. The
/// default count is 20 words. Use kd to find return addresses when the
/// unwinder cannot find them.
#[command(
    names = ["kd"],
    category = "execution and stack",
    kind = Query,
    state = HaltedOrParkedThread,
    python = none,
)]
fn kd(state: &mut ReplState<'_>, #[arg(default = 20, name = "count")] words: u64) -> Result<()> {
    if words == 0 {
        error!("word count must be positive");
        return Ok(());
    }
    // A parked thread has no register file; its stack starts where its
    // walk does.
    let sp = state.ctx.target.builtin_variable_value("csp").or_else(|| {
        state.ctx.parked_windows_thread()?;
        state
            .ctx
            .backtrace(1)
            .ok()?
            .frames
            .first()
            .map(|frame| frame.sp)
    });
    let Some(sp) = sp else {
        error!("the stack pointer is unavailable");
        return Ok(());
    };
    let Some(end) = words
        .checked_mul(8)
        .and_then(|length| sp.checked_add(length))
    else {
        error!("{words} words from {sp:#x} overflow the address space");
        return Ok(());
    };
    let range = AddressRange {
        start: VirtAddr(sp),
        end: VirtAddr(end),
    };
    state.display_symbol_range(&range, 8)
}

/// Decode and show a _KTRAP_FRAME.
///
/// Without an address, .trap uses the saved trap frame of the current thread.
/// Because a trap frame does not identify a process, ntoseye resolves a
/// user-mode frame in the selected process, and shows a warning if the frame
/// address is outside all modules of that process. Before you use .trap,
/// select the thread or process that owns the frame (`.thread`, `.process
/// /p`).
#[command(
    names = [".trap", "trap"],
    category = "execution and stack",
    kind = Action,
    target = Kernel,
    python = none,
)]
fn trap(
    state: &mut ReplState<'_>,
    #[arg(parse = first_address)] address: Option<VirtAddr>,
) -> Result<()> {
    if address.is_none()
        && state
            .ctx
            .target
            .current_thread_pseudo_register("trapframe")
            .is_none()
    {
        report_context_reset(state);
        return Ok(());
    }
    match read_ktrap_frame_at_or_current(&state.ctx.target, address) {
        Ok(frame) => {
            let symbol = trap_frame_rip_symbol(&state.ctx.target, &frame)
                .unwrap_or_else(|| format!("{:#x}", frame.instruction_pointer()));
            let registers = registers_from_trap_frame(&frame);
            let selected = state.select_register_values(0, registers);
            print_ktrap_frame(&frame, Some(&symbol));
            outln!("selected the trap frame's context: frame 00 at {selected:#x}");
            state.warn_if_user_frame_is_out_of_view(frame.instruction_pointer());
        }
        Err(e) => {
            error!("{}", e);
        }
    }

    Ok(())
}

/// `.trap`'s optional address, its first word; it ignores any after.
#[grammar(usage = "[{}]", complete = Expression)]
fn first_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let address = cursor.word().map(|word| cx.eval(&word)).transpose()?;
    cursor.rest();
    Ok(address)
}

impl ReplState<'_> {
    /// Drop any `.frame`/`.cxr`/`.trap` context selection. Called by every
    /// command that changes the execution context (`~Ns`, `vcpu`, `.thread`,
    /// `.process`, run control) so a stale frame never shadows live registers.
    /// Drop a selected frame or context for the stop's default: the vCPU's
    /// registers, or where NT left off when it is halted in the Windows
    /// hypervisor. `.cxr` and `.trap` without an argument go to the vCPU's own
    /// registers instead
    /// ([`crate::session::Session::clear_selected_frame`]).
    pub fn clear_selected_frame(&mut self) {
        self.ctx.reset_to_stop_context();
    }

    fn set_selected_frame(&mut self, selected: SelectedFrame) {
        self.ctx.select_frame(selected);
    }

    pub fn select_register_values(&mut self, index: usize, registers: HashMap<String, u64>) -> u64 {
        let selected = SelectedFrame::from_registers(self.ctx.target.arch(), index, registers);
        let ip = selected.ip;
        self.set_selected_frame(selected);
        ip
    }

    pub fn print_selected_frame(&self, frame: &SelectedFrame, show_registers: bool) {
        let arch = self.ctx.target.arch();
        print_frame_line(&self.frame_line(frame), frame, arch, show_registers);
    }

    /// `.frame`: the selected frame.
    fn show_selected_frame(&self, frame: &SelectedFrame, show_registers: bool) {
        let line = self.frame_line(frame);
        let arch = self.ctx.target.arch();
        print_frame_line(&line, frame, arch, show_registers);
    }

    /// What `.frame` shows for `frame`: its symbol, inline tag and source line.
    fn frame_line(&self, frame: &SelectedFrame) -> FrameLine {
        let target = &self.ctx.target;
        let (symbol, location, inline) = match target.inline_frame(frame.code) {
            Some(inline) => (Some(inline.symbol), inline.location, true),
            None => (
                // Outside every symbol, `k` still names the module and offset.
                target
                    .closest_symbol_current_context(VirtAddr(frame.ip))
                    .or_else(|| {
                        let dtb = frame.dtb.unwrap_or_else(|| target.current_dtb());
                        target.format_code_address(dtb, VirtAddr(frame.ip))
                    }),
                target.frame_source_location(frame.code),
                false,
            ),
        };
        FrameLine {
            symbol: symbol.unwrap_or_else(|| format!("{:#x}", frame.ip)),
            location: location.map(|location| format!("{}:{}", location.file, location.line)),
            inline,
        }
    }

    pub fn recovered_trace(&mut self, limit: usize) -> Result<Option<SeededTrace>> {
        match self.ctx.recovered_backtrace(limit) {
            Ok(trace) => Ok(Some(trace)),
            Err(error) => {
                error!("{}", error);
                Ok(None)
            }
        }
    }

    fn live_register_values(&mut self) -> Option<HashMap<String, u64>> {
        match self.ctx.read_registers() {
            Ok(registers) => Some(
                self.ctx
                    .target
                    .register_values(&self.ctx.register_map, &registers),
            ),
            Err(error) => {
                error!("failed to read registers: {}", error);
                None
            }
        }
    }

    fn exception_context_pointer(&self) -> Option<u64> {
        let event = self.ctx.last_event.as_ref()?;
        let info = event.stop.bugcheck.as_ref()?;
        let candidates: &[usize] = match info.code {
            0x7e | 0x1000_007e => &[3],
            0x8e | 0x1000_008e | 0x1e => &[],
            _ => return None,
        };
        candidates
            .iter()
            .map(|index| info.parameters[*index])
            .find(|address| looks_like_kernel_pointer(self.ctx.target.arch(), *address))
    }

    fn print_stack_parameters(&self, trace: &StackTrace) -> Result<()> {
        let mut printed_header = false;
        // Whether any frame is in a procedure private symbols describe:
        // without one, public symbols record no parameters to locate.
        let mut private = false;
        for (index, frame) in trace.frames.iter().enumerate() {
            let Some(locals) = self.ctx.target.frame_locals(frame.code)? else {
                continue;
            };
            private = true;
            let parameters: Vec<_> = locals.iter().filter(|local| local.is_parameter).collect();
            if parameters.is_empty() {
                continue;
            }
            if !printed_header {
                print_section("parameters (PDB locations)");
                printed_header = true;
            }
            for parameter in parameters {
                let location = parameter.location.describe();
                outln!(
                    "  {:02}  {:<24} {:<20} {}",
                    index,
                    parameter.name,
                    parameter.type_name,
                    location
                );
            }
        }
        if !printed_header {
            let note = if private {
                "no parameters: the private symbols record none for these frames"
            } else {
                "no parameter locations: no private symbols cover these frames (public symbols record none)"
            };
            outln!("{}", ui::muted(note));
        }
        Ok(())
    }

    /// A trap frame names no process, so its user-mode program counter is
    /// resolved and unwound in the selected address space, which need not be
    /// the one the thread ran in. Say so when nothing there covers it.
    fn warn_if_user_frame_is_out_of_view(&self, pc: u64) {
        let target = &self.ctx.target;
        if target.arch().paging().is_kernel_address(VirtAddr(pc)) {
            return;
        }
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        if try_format_symbol(target, &trace, pc).is_some() {
            return;
        }
        let space = match trace.description.as_str() {
            "kernel" => "the kernel address space".to_string(),
            UNKNOWN_CONTEXT => "the selected address space".to_string(),
            process => process.to_string(),
        };
        diagnostics::print_warning(format!(
            "{pc:#x} is a user-mode address outside every module of {}; user-mode frames \
             resolve in the thread's own process, so select it first with .thread <ethread> \
             or .process /p <pid>",
            space
        ));
    }
}

pub fn registers_from_trap_frame(frame: &KtrapFrame) -> HashMap<String, u64> {
    let saved = SavedThreadRegisters::from(frame);
    let arch = frame.arch();
    let aliases = arch.register_synonyms().iter().map(|&(_, alias)| alias);
    arch.general_registers()
        .iter()
        .copied()
        .chain(aliases)
        .filter_map(|name| Some((name.to_string(), saved.get(name)?)))
        .collect()
}

fn print_exception_record(record: &ExceptionRecord) {
    let address = record.record_address.unwrap_or(0);
    if address != 0 {
        outln!("EXCEPTION_RECORD {}", ui::addr(address));
    } else {
        outln!("EXCEPTION_RECORD of the current exception");
    }
    let code = match ntstatus_name(record.code) {
        Some(name) => format!("{name} ({:#010x})", record.code),
        None => format!("{:#010x}", record.code),
    };
    let mut fields = vec![
        ("ExceptionAddress".to_string(), ui::addr(record.address)),
        ("ExceptionCode".to_string(), code),
        ("ExceptionFlags".to_string(), exception_flags(record.flags)),
        (
            "ExceptionRecord".to_string(),
            ui::addr_opt(VirtAddr(record.nested)),
        ),
        (
            "NumberParameters".to_string(),
            record.parameters.len().to_string(),
        ),
    ];
    fields.extend(
        record
            .parameters
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("Parameter[{index}]"), ui::addr(*value))),
    );
    let width = fields.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, value) in fields {
        outln!("  {name:<width$} : {value}");
    }
}

/// `ExceptionFlags` as a flag set: the value, then the `EXCEPTION_*` names
/// of its bits.
fn exception_flags(flags: u32) -> String {
    let names = exception_flag_names(flags);
    if names.is_empty() {
        format!("{flags:#x}")
    } else {
        format!("{flags:#x} ({})", names.join(" | "))
    }
}

/// `r`'s text: the general-purpose grid, then the control (when `control`)
/// and segment registers.
fn print_register_grid(register_map: &RegisterMap, regs: &[u8], arch: Arch, control: bool) {
    print_registers(register_map, arch, regs, None, None);
    let control = if control {
        arch.control_registers()
    } else {
        &[]
    };
    let blocks = [control, arch.selector_registers()];
    for block in blocks.into_iter().filter(|block| !block.is_empty()) {
        outln!();
        print_shown_registers(register_map, regs, block);
    }
}

/// `rows` of registers below the general ones, their values in the columns
/// of the grid above: labels at least as wide as its names.
fn print_shown_registers(register_map: &RegisterMap, regs: &[u8], rows: &[&[ShownRegister]]) {
    let width = rows
        .iter()
        .flat_map(|row| row.iter())
        .map(|register| register.label.len())
        .max()
        .unwrap_or(0)
        .max(3);
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(index, register)| {
                let digits = register.digits;
                let value = match register_map.read_u64(register.name, regs) {
                    Ok(value) => format!("{value:0digits$x}"),
                    Err(_) if index + 1 == row.len() => "-".to_string(),
                    Err(_) => format!("{:<digits$}", "-"),
                };
                format!("{:<width$} {value}", register.label)
            })
            .collect();
        outln!("{}", cells.join("   "));
    }
}

pub fn print_indexed_stacktrace(
    arch: Arch,
    trace: &RecoveredStackTrace,
    display_limit: usize,
    columns: StackColumns,
    selected_index: Option<usize>,
) {
    let mut previous_sp = None;
    for (index, recovered) in trace.frames.iter().take(display_limit).enumerate() {
        let frame = &recovered.frame;
        if index > 0
            && let Some(label) = crossing(arch, &trace.frames[index - 1].frame, frame)
        {
            outln!("{}", crossing_line(label, 4));
        }
        let marker = if selected_index == Some(index) {
            "*"
        } else {
            " "
        };
        let symbol = if frame.inline {
            format!("{}  {}", call_site(frame), inline_tag())
        } else {
            call_site(frame)
        };
        let provenance = if columns.provenance {
            format!("  [{}]", frame.source.as_str())
        } else if matches!(frame.source, FrameSource::Scan | FrameSource::Prolog) {
            // A guess, by a stack scan or by reading a prolog, is marked
            // always, as the stop's stack marks it.
            format!("  [{}]", frame.source.as_str())
        } else {
            String::new()
        };
        let frame_size = if columns.frame_size {
            let size = if frame.inline {
                frame_size_cell(None, frame.sp)
            } else {
                frame_size_cell(previous_sp.replace(frame.sp), frame.sp)
            };
            format!("{size} ")
        } else {
            String::new()
        };
        let location = frame
            .source_location
            .as_ref()
            .map(|location| format!("  {}", ui::muted(&format_source_location(location))))
            .unwrap_or_default();
        outln!(
            "{}{:02} {}{}  {}{}{}",
            marker,
            index,
            frame_size,
            ui::addr(frame.sp),
            ui::addr(frame.ip),
            format!("  {symbol}"),
            format!("{provenance}{location}")
        );
    }
    let hidden = trace.frames.len().saturating_sub(display_limit) + trace.truncated;
    if hidden > 0 {
        outln!("{}", more_frames(hidden));
    }
}

/// `.fnent` in WinDbg's order: the entry, its unwind info, then each chained
/// parent's.
fn print_function_entry(detail: &FunctionEntry) {
    let base = detail.image_base;
    let va = |rva: u32| ui::addr(base.wrapping_add(u64::from(rva)));
    for (index, entry) in detail.entries.iter().enumerate() {
        if index > 0 {
            outln!();
        }
        if index == 0 {
            outln!(
                "{} in {} (image base {})",
                ui::symbol(&entry.symbol),
                detail.module,
                ui::addr(base)
            );
        } else {
            outln!("{} {}", ui::label("chained to"), ui::symbol(&entry.symbol));
        }
        outln!(
            "  BeginAddress      = {:08x}  {}",
            entry.begin_rva,
            ui::addr(entry.begin)
        );
        outln!(
            "  EndAddress        = {:08x}  {}",
            entry.end_rva,
            ui::addr(entry.end)
        );
        if matches!(entry.unwind, Some(Unwind::Packed(_))) {
            outln!("  UnwindData        = {:08x}  (packed)", entry.unwind_data);
        } else {
            outln!(
                "  UnwindInfoAddress = {:08x}  {}",
                entry.unwind_data,
                va(entry.unwind_data)
            );
        }
        match &entry.unwind {
            None => {
                outln!();
                outln!("{}", ui::muted("the unwind info is unreadable"));
            }
            Some(Unwind::Amd64(info)) => {
                print_section(&format!(
                    "unwind info at {} ({:#x} bytes)",
                    va(entry.unwind_data),
                    info.size
                ));
                let flag_names: Vec<&str> = [(1, "EHANDLER"), (2, "UHANDLER"), (4, "CHAININFO")]
                    .into_iter()
                    .filter(|(bit, _)| info.flags & bit != 0)
                    .map(|(_, name)| name)
                    .collect();
                let mut fields = vec![
                    ("version", info.version.to_string()),
                    (
                        "flags",
                        if flag_names.is_empty() {
                            format!("{:#x}", info.flags)
                        } else {
                            format!("{:#x} ({})", info.flags, flag_names.join(" | "))
                        },
                    ),
                    ("prolog size", format!("{:#x}", info.prolog_size)),
                    ("codes", info.code_count.to_string()),
                ];
                if let Some(register) = info.frame_register {
                    fields.push(("frame register", register.to_string()));
                    fields.push(("frame offset", format!("{:#x}", info.frame_offset)));
                }
                handler_fields(&mut fields, &info.handler);
                print_unwind_fields(&fields);
                outln!("  unwind codes");
                for code in &info.codes {
                    outln!(
                        "    {:02}: offs {:#x}, unwind op {}, op info {}  {}",
                        code.slot,
                        code.code_offset,
                        code.op,
                        code.op_info,
                        code.description
                    );
                }
            }
            Some(Unwind::Packed(packed)) => {
                print_section("packed unwind data");
                print_unwind_fields(&[
                    ("flag", packed.flag.to_string()),
                    ("RegF", packed.reg_f.to_string()),
                    ("RegI", packed.reg_i.to_string()),
                    ("H", u8::from(packed.homes_arguments).to_string()),
                    ("CR", packed.cr.to_string()),
                    ("frame size", format!("{:#x}", packed.frame_size)),
                ]);
                outln!("  prolog codes");
                print_arm64_codes(&packed.codes);
            }
            Some(Unwind::Xdata(xdata)) => {
                print_section(&format!(
                    "unwind info at {} ({:#x} bytes)",
                    va(entry.unwind_data),
                    xdata.size
                ));
                let mut fields = vec![
                    ("version", xdata.version.to_string()),
                    ("X", u8::from(xdata.exception_data).to_string()),
                    ("E", u8::from(xdata.epilog_in_header).to_string()),
                    (
                        if xdata.epilog_in_header {
                            "epilog code index"
                        } else {
                            "epilog count"
                        },
                        xdata.epilog_count.to_string(),
                    ),
                    ("code words", xdata.code_words.to_string()),
                ];
                handler_fields(&mut fields, &xdata.handler);
                print_unwind_fields(&fields);
                if !xdata.epilog_scopes.is_empty() {
                    outln!("  epilog scopes");
                }
                for scope in &xdata.epilog_scopes {
                    outln!(
                        "    at +{:#x}, codes from index {:#x}",
                        scope.start_offset,
                        scope.first_code
                    );
                }
                outln!("  unwind codes");
                print_arm64_codes(&xdata.codes);
            }
        }
    }
    if let Some(reason) = &detail.incomplete {
        outln!();
        outln!("{}", ui::muted(reason));
    }
}

/// The fields of `.fnent`'s unwind block, two spaces in, their values in one
/// column.
fn print_unwind_fields(fields: &[(&str, String)]) {
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, value) in fields {
        outln!("  {label:<width$}  {value}");
    }
}

/// The exception or termination handler of an unwind block, as its fields.
fn handler_fields(fields: &mut Vec<(&'static str, String)>, handler: &Option<UnwindHandler>) {
    if let Some(handler) = handler {
        fields.push((
            "handler",
            format!(
                "{}  {}",
                ui::addr(handler.address),
                ui::symbol(&handler.symbol)
            ),
        ));
        fields.push(("handler data", ui::addr(handler.data)));
    }
}

fn print_arm64_codes(codes: &[Arm64UnwindCode]) {
    for code in codes {
        let bytes: Vec<String> = code
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        outln!(
            "    {:02x}: {:<12} {}",
            code.index,
            bytes.join(" "),
            code.description
        );
    }
}
