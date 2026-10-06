use std::collections::HashMap;

use owo_colors::OwoColorize;

use crate::bugchecks::{bugcheck_trap_frame_address, looks_like_kernel_pointer};
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::diagnostics;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::session::ExceptionRecord;
use crate::target::{SavedThreadRegisters, SelectedFrame, lookup_register};
use crate::trapframe::{KtrapFrame, read_ktrap_frame_at_or_current, trap_frame_rip_symbol};
use crate::triage_report::exception_code_name;
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    Arm64CodeDetail, Arm64UnwindDetail, FrameSource, FunctionEntryDetail, HandlerDetail,
    RecoveredStackTrace, StackTrace, UNKNOWN_CONTEXT, UnwindDetail,
    build_stacktrace_with_register_values, build_thread_stacktrace, halted_in_windows_hypervisor,
    resolve_thread_trace_context, saved_vtls, try_format_symbol,
};

use crate::repl::*;

const MAX_FRAME_INDEX: usize = 4095;

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
fn print_frame_line(line: &FrameLine, frame: &SelectedFrame, show_registers: bool) {
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
    outln!(
        "{} {} {}  {}{tag}{location}",
        ui::muted(&format!("#{:02}", frame.index)),
        ui::addr(frame.sp),
        ui::addr(frame.ip),
        ui::symbol(&line.symbol),
    );
    if let Some(base) = frame.frame_base {
        outln!("  frame base {}", ui::addr(base));
    }
    if show_registers {
        print_sparse_registers(&frame.registers, Some("  registers:"), 4);
    }
    outln!();
}

repl_command! {
    cmd_frame;
    names: [".frame", "frame"],
    usage: ".frame [/r] [N]",
    summary: "Select or show a stack frame.",
    details: "N is a zero-based frame number that counts inline frames, as k does. /r also shows the recovered registers of the frame. When you select an inline frame, dv, ls, lsa, and local names in expressions use the function that the compiler inlined there, and the registers are those of the frame that contains it.",
    completion: Expression,
    run_state: HaltedOrParkedThread,
}

repl_command! {
    cmd_fnent;
    names: [".fnent"],
    usage: ".fnent <address>",
    summary: "Show the function table entry and unwind info of the function that contains an address.",
    details: "Shows the RUNTIME_FUNCTION that covers the address (the begin, end, and unwind info RVAs), then its unwind data. On AMD64, the unwind data is the UNWIND_INFO version, flags, prolog size, frame register, and frame offset, each unwind code with its operands, and the exception or termination handler. After a chained entry, .fnent shows the entry of each parent. On ARM64, it shows the fields of packed unwind data (flag, RegF, RegI, H, CR, frame size) and the prolog codes that they represent. For an .xdata record, it shows the header, the epilog scopes, each unwind code with the instruction that it undoes, and the exception handler. If a function table is paged out, .fnent reads it from the image file on disk.",
    completion: Expression,
}

repl_command! {
    cmd_cxr;
    names: [".cxr"],
    usage: ".cxr [address]",
    summary: "Select a CONTEXT record, or reset the selected context.",
    details: "Without an address, .cxr goes back to the vCPU's own registers. At a stop in the Windows hypervisor, these are the registers of the hypervisor, which do not show where NT left off.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ecxr();
    names: [".ecxr"],
    usage: ".ecxr",
    summary: "Select the current exception context.",
    run_state: Halted,
}

repl_command! {
    cmd_vtlcxr;
    names: [".vtlcxr"],
    usage: ".vtlcxr [0|1]",
    summary: "Select the VTL0 or VTL1 context that the Windows hypervisor saved for a vCPU halted in the hypervisor.",
    details: "Use this command for a vCPU that stopped in the Windows hypervisor (VBS). It reads the saved state of each VTL of the virtual processor from the Enlightened VMCS page of that VTL, lists these states, and selects the VTL0 state, so that r, k, and u show where NT left off. The VM must expose hv-evmcs, and at the first use in each boot, the command scans host RAM for the pages. The context has RIP, RSP, flags, control registers, and segment registers from the Enlightened VMCS. For the current VTL it also has the other general-purpose registers, read where the hypervisor's VM-exit entry code saved them (experimental), and the command says why when they are missing. .vtlcxr 1 selects the saved VTL1 state instead, in the secure kernel's address space with its symbols, which it loads first as .vtl 1 does: k walks the secure kernel's stack from where VTL1 left off, usually its VTL return, and the context is read-only, as at a VTL1 stop: .vtlcxr goes back to the VTL0 state. Its general-purpose registers are known only when VTL1 made the hypervisor's last exit. A stop in the hypervisor selects the VTL0 state automatically. .cxr goes back to the registers of the hypervisor, and .vtlcxr then selects the VTL0 state again. See 'Where NT left off under the hypervisor' in the VBS guide.",
    run_state: Halted,
}

repl_command! {
    cmd_exr;
    names: [".exr"],
    usage: ".exr <address|-1>",
    summary: "Show an EXCEPTION_RECORD64.",
    completion: Expression,
}

repl_command! {
    cmd_registers;
    names: ["r", "registers"],
    usage: "r [register[=expression]]",
    summary: "Show the CPU registers, or set the value of one register.",
    details: "r shows a 128-bit register (xmm0, ARM64 v0) at full width, and you set it through its 64-bit halves (xmm0l/xmm0h, v0l/v0h). For a vCPU stopped in VTL1, r shows the VTL1 registers as read-only. The .vtl 1 memory view has no registers.",
    run_state: HaltedOrParkedThread,
}

repl_command! {
    cmd_k;
    names: ["kn", "k", "kb", "kp", "kv", "kf"],
    usage: "kn|k|kb|kp|kv|kf [count]",
    summary: "Show a stack.",
    details: "kp adds the PDB parameter locations, kv adds the provenance of each frame, and kf adds the frame sizes. A call that the compiler inlined is a separate frame with the tag [inline], which is above the frame that contains it and shows the addresses of that frame. The inline frame has the name of the inlined function and shows the source line in that function, and its caller shows the line of the call. Frame numbers include inline frames. In kf output, the column after the frame number is the stack memory between the frame and the physical frame before it, in hex. This column is blank for the first frame, for inline frames, and where the walk moves to a different stack.",
    run_state: HaltedOrParkedThread,
}

repl_command! {
    cmd_kd;
    names: ["kd"],
    usage: "kd [count]",
    summary: "Show raw stack words from the stack pointer, with the symbol of each value that resolves to one.",
    details: "kd is the same as `dps @$csp L<count>` and shows one pointer-sized word on each line, starting at the stack pointer of the selected frame. The default count is 20 words. Use kd to find return addresses when the unwinder cannot find them.",
    completion: Expression,
    run_state: HaltedOrParkedThread,
}

repl_command! {
    cmd_trap;
    names: [".trap", "trap"],
    usage: ".trap [address-expression]",
    summary: "Decode and show a _KTRAP_FRAME.",
    details: "Without an address, .trap uses the saved trap frame of the current thread. Because a trap frame does not identify a process, ntoseye resolves a user-mode frame in the selected process, and shows a warning if the frame address is outside all modules of that process. Before you use .trap, select the thread or process that owns the frame (`.thread`, `.process /p`).",
    completion: Expression,
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
        let selected = SelectedFrame::from_registers(index, registers);
        let ip = selected.ip;
        self.set_selected_frame(selected);
        ip
    }

    pub fn print_selected_frame(&self, frame: &SelectedFrame, show_registers: bool) {
        print_frame_line(&self.frame_line(frame), frame, show_registers);
    }

    /// `.frame`: the selected frame, natively in Tern.
    fn show_selected_frame(&self, frame: &SelectedFrame, show_registers: bool) {
        let line = self.frame_line(frame);
        #[cfg(feature = "cli")]
        native::render(
            || native::inspect::frame(&line, frame, show_registers),
            || print_frame_line(&line, frame, show_registers),
        );
        #[cfg(not(feature = "cli"))]
        print_frame_line(&line, frame, show_registers);
    }

    /// What `.frame` shows for `frame`: its symbol, inline tag and source line.
    fn frame_line(&self, frame: &SelectedFrame) -> FrameLine {
        let target = &self.ctx.target;
        let (symbol, location, inline) = match target.inline_frame(frame.code) {
            Some(inline) => (Some(inline.symbol), inline.location, true),
            None => (
                target.closest_symbol_current_context(VirtAddr(frame.ip)),
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

    fn cmd_frame(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut show_registers = false;
        let mut index = None;
        for arg in &invocation.argv {
            match arg.as_ref() {
                "/r" | "-r" => show_registers = true,
                value if index.is_none() => {
                    let Some(parsed) = self.eval_or_report(value) else {
                        return Ok(());
                    };
                    index = Some(usize::try_from(parsed.0).unwrap_or(usize::MAX));
                }
                _ => {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
            }
        }

        let Some(index) = index else {
            if let Some(frame) = self.ctx.target.selected_frame.as_ref() {
                self.show_selected_frame(frame, show_registers);
                return Ok(());
            }
            let Some((recovered, seed, live)) = self.recovered_trace(1)? else {
                return Ok(());
            };
            let Some(selected) = SelectedFrame::from_recovered(&recovered, 0, Some(&seed), live)
            else {
                error!("current frame is unavailable");
                return Ok(());
            };
            self.show_selected_frame(&selected, show_registers);
            return Ok(());
        };
        if index > MAX_FRAME_INDEX {
            error!("frame index is too large");
            return Ok(());
        }

        let limit = index.saturating_add(1);
        let Some((recovered, seed, live)) = self.recovered_trace(limit)? else {
            return Ok(());
        };
        let Some(selected) = SelectedFrame::from_recovered(&recovered, index, Some(&seed), live)
        else {
            error!("frame {} is unavailable", index);
            return Ok(());
        };
        self.set_selected_frame(selected.clone());
        self.show_selected_frame(&selected, show_registers);
        Ok(())
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

    fn cmd_cxr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            self.ctx.clear_selected_frame();
            outln!("selected context reset\n");
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(address) = self.eval_or_report(text) else {
            return Ok(());
        };
        let registers = match self.ctx.read_context_record(address) {
            Ok(registers) => registers,
            Err(error) => {
                error!(
                    "could not read a CONTEXT at {}: {error}",
                    ui::addr(address.0)
                );
                return Ok(());
            }
        };
        let selected = SelectedFrame::from_registers(0, registers);
        self.set_selected_frame(selected.clone());
        outln!("selected context {}", ui::addr(address.0));
        self.print_selected_frame(&selected, false);
        Ok(())
    }

    fn cmd_vtlcxr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let vtl = match (invocation.arg(0), invocation.argv.len()) {
            (None, _) | (Some("0"), 1) => 0,
            (Some("1"), 1) => 1,
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        if let Err(error) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {error}");
            return Ok(());
        }
        let regs = match self.ctx.read_registers() {
            Ok(regs) => regs,
            Err(error) => {
                error!("failed to read registers: {error}");
                return Ok(());
            }
        };
        let target = &self.ctx.target;
        let map = &self.ctx.register_map;
        let (Ok(cr3), Ok(rip)) = (
            map.read_u64(target.arch().dtb_register(), &regs),
            map.read_u64("rip", &regs),
        ) else {
            error!("the vCPU's CR3 and RIP are unavailable");
            return Ok(());
        };
        if !halted_in_windows_hypervisor(target, cr3, rip) {
            error!(
                "{} is not halted in the Windows hypervisor",
                ui::thread_id(&self.ctx.current_thread)
            );
            return Ok(());
        }
        let processor = processor_index_from_backend_thread_id(&self.ctx.current_thread);
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
            && let Err(error) = self.ctx.target.load_secure_kernel_symbols()
        {
            error!("the secure kernel's symbols: {error}");
        }
        let selected = SelectedFrame::from_registers(0, chosen.context.registers());
        self.set_selected_frame(selected.clone());
        if vtl == 1 {
            self.caches.refresh_symbol_context(&self.ctx.target);
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
        self.print_selected_frame(&selected, false);
        Ok(())
    }

    fn cmd_ecxr(&mut self) -> Result<()> {
        if let Some(info) = self
            .ctx
            .last_event
            .as_ref()
            .and_then(|event| event.stop.bugcheck.as_ref())
            && matches!(info.code, 0x8e | 0x1000_008e)
        {
            let Some(address) = bugcheck_trap_frame_address(info) else {
                error!("no trap frame is available for the current bugcheck");
                return Ok(());
            };
            match read_ktrap_frame_at_or_current(&self.ctx.target, Some(VirtAddr(address))) {
                Ok(frame) => {
                    let registers = registers_from_trap_frame(&frame);
                    let selected = SelectedFrame::from_registers(0, registers);
                    self.set_selected_frame(selected.clone());
                    outln!("exception trap frame {}", ui::addr(address));
                    self.print_selected_frame(&selected, false);
                }
                Err(error) => {
                    error!(
                        "could not read exception trap frame at {}: {}",
                        ui::addr(address),
                        error
                    );
                }
            }
            return Ok(());
        }

        if let Some(address) = self.exception_context_pointer() {
            match self.ctx.read_context_record(VirtAddr(address)) {
                Ok(registers) => {
                    let selected = SelectedFrame::from_registers(0, registers);
                    self.set_selected_frame(selected.clone());
                    outln!("exception context {}", ui::addr(address));
                    self.print_selected_frame(&selected, false);
                }
                Err(error) => error!(
                    "could not read exception context at {}: {error}",
                    ui::addr(address)
                ),
            }
            return Ok(());
        }

        // KD exception stops expose the exception context as the current
        // backend register file. Do not use this for a bugcheck stop: that
        // context is normally KeBugCheck rather than the faulting exception.
        let is_bugcheck = self
            .ctx
            .last_event
            .as_ref()
            .is_some_and(|event| event.stop.is_bugcheck);
        if !is_bugcheck {
            let Some(registers) = self.live_register_values() else {
                error!("exception context is unavailable");
                return Ok(());
            };
            let selected = SelectedFrame::from_registers(0, registers);
            self.set_selected_frame(selected.clone());
            outln!("exception context from current stop");
            self.print_selected_frame(&selected, false);
            return Ok(());
        }

        error!("no exception context is available for the current bugcheck");
        Ok(())
    }

    fn live_register_values(&mut self) -> Option<HashMap<String, u64>> {
        match self.ctx.read_registers() {
            Ok(registers) => Some(self.ctx.register_map.to_hashmap(&registers)),
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
            .find(|address| looks_like_kernel_pointer(*address))
    }

    fn cmd_exr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        if text == "-1" {
            self.print_current_exception_record();
            return Ok(());
        }
        let Some(address) = self.eval_or_report(text) else {
            return Ok(());
        };
        let record = match self.ctx.read_exception_record(address) {
            Ok(record) => record,
            Err(error) => {
                error!(
                    "could not read an EXCEPTION_RECORD64 at {}: {error}",
                    ui::addr(address.0)
                );
                return Ok(());
            }
        };
        print_exception_record(address.0, &record);
        Ok(())
    }

    fn print_current_exception_record(&self) {
        let Some(record) = self.ctx.current_exception_record() else {
            error!("no current exception record");
            return;
        };
        print_exception_record(0, &record);
    }

    fn cmd_registers(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // A live frame 0 (`.frame 0`, or the frame an editor client keeps
        // selected) is the vCPU's own register file. Only a recovered context
        // is shown from its snapshot and refused assignment.
        if let Some(frame) = self
            .ctx
            .target
            .selected_frame
            .as_ref()
            .filter(|frame| !frame.is_live())
        {
            let tail = invocation.raw_tail.trim();
            if tail.contains('=') {
                error!(
                    "cannot assign registers while frame {} is selected; use `.cxr`/`.frame` reset first",
                    frame.index
                );
                return Ok(());
            }
            if !tail.is_empty() && tail.split_whitespace().count() != 1 {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
            outln!("registers (frame {})", frame.index);
            if !tail.is_empty() {
                let name = tail.trim_start_matches('@');
                let lowered_name = name.to_ascii_lowercase();
                let requested = match lowered_name.as_str() {
                    "efl" | "rflags" => "eflags",
                    name => name,
                };
                if let Some(value) = lookup_register(&frame.registers, requested) {
                    outln!("{}={}", requested, ui::addr(value));
                } else {
                    error!(
                        "register not recovered in frame {}: {}",
                        frame.index, requested
                    );
                }
            } else {
                print_sparse_registers(&frame.registers, None, 2);
            }
            outln!();
            return Ok(());
        }
        if self.ctx.parked_windows_thread().is_some() {
            error!(
                "selected Windows thread is parked and has no coherent register context; use `vcpu <id>`"
            );
            return Ok(());
        }
        // A VTL1 stop is observed, never altered: the vCPU resumes VTL1 code
        // exactly as it was trapped.
        if self.ctx.target.in_secure_address_space() && invocation.raw_tail.contains('=') {
            error!("VTL1 registers are read-only; the vCPU is stopped in VTL1");
            return Ok(());
        }
        if let Err(e) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {e}");
            return Ok(());
        }

        let mut regs = match self.ctx.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {e}");
                return Ok(());
            }
        };
        self.ctx.target.registers = Some(self.ctx.register_map.to_hashmap(&regs));

        if !invocation.raw_tail.trim().is_empty() {
            let tail = invocation.raw_tail.trim();
            let Some((name, expression)) = tail.split_once('=') else {
                if tail.split_whitespace().count() != 1 {
                    outln!("{}\n", command_help(invocation.name));
                    return Ok(());
                }
                let requested_name = tail.trim_start_matches('@').to_ascii_lowercase();
                let name = match requested_name.as_str() {
                    "efl" | "rflags" => "eflags",
                    name => name,
                };
                match self.ctx.register_map.read_u64(name, &regs) {
                    Ok(value) => outln!("{name}={}", ui::addr(value)),
                    Err(Error::RegisterTooWide(_)) => {
                        match self.ctx.register_map.read_u128(name, &regs) {
                            Ok(value) => outln!("{name}={value:032x}"),
                            Err(e) => error!("{e}"),
                        }
                    }
                    Err(e) => error!("{e}"),
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
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
            let Some(VirtAddr(value)) = self.eval_or_report(expression) else {
                return Ok(());
            };
            if let Err(e) = self.ctx.write_register(name, value) {
                error!("failed to write register {name}: {e}");
                return Ok(());
            }
            regs = match self.ctx.read_registers() {
                Ok(regs) => regs,
                Err(e) => {
                    error!("register written, but refresh failed: {e}");
                    return Ok(());
                }
            };
            self.ctx.target.registers = Some(self.ctx.register_map.to_hashmap(&regs));
            outln!("@{name} = {}\n", ui::addr(value));
        }

        let register_map = &self.ctx.register_map;
        let arch = self.ctx.target.arch();
        let print_text = || print_register_grid(register_map, &regs, arch);
        #[cfg(feature = "cli")]
        native::render(
            || {
                native::frames::registers(
                    &|name: &str| register_map.read_u64(name, &regs).ok(),
                    arch == Arch::Arm64,
                )
            },
            print_text,
        );
        #[cfg(not(feature = "cli"))]
        print_text();

        Ok(())
    }

    fn print_stack_parameters(&self, trace: &StackTrace, frame_offset: usize) -> Result<()> {
        let mut printed_header = false;
        for (index, frame) in trace.frames.iter().enumerate() {
            let Some(locals) = self.ctx.target.frame_locals(frame.code)? else {
                continue;
            };
            let parameters: Vec<_> = locals.iter().filter(|local| local.is_parameter).collect();
            if parameters.is_empty() {
                continue;
            }
            if !printed_header {
                outln!("{}", ui::label("parameters (PDB locations)"));
                printed_header = true;
            }
            for parameter in parameters {
                let location = parameter.location.describe();
                outln!(
                    "  #{:02}  {:<24} {:<20} {}",
                    index + frame_offset,
                    parameter.name,
                    parameter.type_name,
                    location
                );
            }
        }
        if !printed_header {
            outln!(
                "{}",
                ui::muted("parameter locations unavailable from loaded private symbols")
            );
        }
        Ok(())
    }

    fn cmd_k(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let columns = StackColumns {
            provenance: invocation.name.eq_ignore_ascii_case("kv"),
            frame_size: invocation.name.eq_ignore_ascii_case("kf"),
        };
        let frame_limit = match invocation.arg(0) {
            Some(count) => match self.eval_or_report(count) {
                Some(count) => usize::try_from(count.0).unwrap_or(usize::MAX).min(4096),
                None => return Ok(()),
            },
            None => 64,
        };
        if self.ctx.parked_windows_thread().is_some() && self.ctx.target.selected_frame.is_none() {
            let trace = match self.ctx.backtrace(frame_limit) {
                Ok(trace) => trace,
                Err(error) => {
                    error!("failed to unwind parked thread stack: {error}");
                    return Ok(());
                }
            };
            if invocation.name.eq_ignore_ascii_case("kp") {
                print_stacktrace_data_with(&trace, frame_limit, false, columns);
                self.print_stack_parameters(&trace, 0)?;
                outln!();
                return Ok(());
            }
            let print_text = || {
                print_stacktrace_data_with(&trace, frame_limit, false, columns);
                outln!();
            };
            #[cfg(feature = "cli")]
            native::render(
                || native::frames::stack(&trace, frame_limit, columns, 0, None),
                print_text,
            );
            #[cfg(not(feature = "cli"))]
            print_text();
            return Ok(());
        }

        let trace = if let Some(selected) = self
            .ctx
            .target
            .selected_frame
            .as_ref()
            .filter(|selected| selected.thread.is_some())
        {
            // A frame of a parked thread's walk: its frames from there on are
            // that walk's, not a new walk from the frame's registers.
            let skip = selected.index;
            match self
                .ctx
                .recovered_backtrace(skip.saturating_add(frame_limit))
            {
                Ok((mut trace, _, _)) => {
                    trace.frames.drain(..skip.min(trace.frames.len()));
                    trace
                }
                Err(error) => {
                    error!("failed to unwind parked thread stack: {error}");
                    return Ok(());
                }
            }
        } else if let Some(selected) = self.ctx.target.selected_frame.as_ref() {
            build_stacktrace_with_register_values(
                &self.ctx.target,
                &self.ctx.register_map,
                &selected.registers,
                frame_limit,
            )
        } else {
            if let Err(e) = self
                .ctx
                .backend
                .set_current_thread(&self.ctx.current_thread)
            {
                error!("failed to select execution context: {e}");
                return Ok(());
            }
            let regs = match self.ctx.read_registers() {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to read registers: {e}");
                    return Ok(());
                }
            };
            build_thread_stacktrace(
                &self.ctx.target,
                &self.ctx.register_map,
                &regs,
                self.ctx.target.windows_thread_selection.as_ref(),
                frame_limit,
            )
        };
        let offset = self
            .ctx
            .target
            .selected_frame
            .as_ref()
            .map(|frame| frame.index)
            .unwrap_or(0);
        let selected = self.ctx.target.selected_frame.as_ref().map(|_| offset);
        if !invocation.name.eq_ignore_ascii_case("kp") {
            let print_text = || {
                print_indexed_stacktrace(&trace, frame_limit, offset, columns, selected);
                outln!();
            };
            #[cfg(feature = "cli")]
            native::render(
                || {
                    let plain = StackTrace {
                        frames: trace
                            .frames
                            .iter()
                            .map(|frame| frame.frame.clone())
                            .collect(),
                        truncated: trace.truncated,
                    };
                    native::frames::stack(&plain, frame_limit, columns, offset, selected)
                },
                print_text,
            );
            #[cfg(not(feature = "cli"))]
            print_text();
            return Ok(());
        }
        print_indexed_stacktrace(&trace, frame_limit, offset, columns, selected);
        let plain = StackTrace {
            frames: trace
                .frames
                .iter()
                .map(|frame| frame.frame.clone())
                .collect(),
            truncated: trace.truncated,
        };
        self.print_stack_parameters(&plain, offset)?;
        outln!();

        Ok(())
    }

    fn cmd_kd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const DEFAULT_WORDS: u64 = 20;
        let words = match invocation.arg(0) {
            Some(count) => match self.eval_or_report(count) {
                Some(count) if count.0 > 0 => count.0,
                Some(_) => {
                    error!("word count must be positive");
                    return Ok(());
                }
                None => return Ok(()),
            },
            None => DEFAULT_WORDS,
        };
        // A parked thread has no register file; its stack starts where its
        // walk does.
        let sp = self.ctx.target.builtin_variable_value("csp").or_else(|| {
            self.ctx.parked_windows_thread()?;
            self.ctx
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
            error!(
                "{words:#x} words from {} overflow the address space",
                ui::addr(sp)
            );
            return Ok(());
        };
        let range = AddressRange {
            start: VirtAddr(sp),
            end: VirtAddr(end),
        };
        self.display_symbol_range(&range, 8)
    }

    fn cmd_fnent(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address_arg = require_arg!(invocation, 0, ".fnent");
        let Some(address) = self.eval_or_report(address_arg) else {
            return Ok(());
        };
        match self.ctx.function_entry(address) {
            Ok(detail) => print_function_entry(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_trap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address = match invocation.arg(0) {
            Some(expr) => match self.eval_or_report(expr) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            None => None,
        };
        if address.is_none()
            && self
                .ctx
                .target
                .current_thread_pseudo_register("trapframe")
                .is_none()
        {
            self.ctx.clear_selected_frame();
            outln!("selected context reset\n");
            return Ok(());
        }
        match read_ktrap_frame_at_or_current(&self.ctx.target, address) {
            Ok(frame) => {
                let symbol = trap_frame_rip_symbol(&self.ctx.target, &frame)
                    .unwrap_or_else(|| format!("{:#x}", frame.instruction_pointer()));
                let registers = registers_from_trap_frame(&frame);
                let selected = self.select_register_values(0, registers);
                let print_text = || {
                    print_ktrap_frame(&frame, Some(&symbol));
                    outln!("selected trap context frame 00 at {}", ui::addr(selected));
                };
                #[cfg(feature = "cli")]
                native::render(
                    || native::frames::trap(&frame, Some(&symbol), selected),
                    print_text,
                );
                #[cfg(not(feature = "cli"))]
                print_text();
                self.warn_if_user_frame_is_out_of_view(frame.instruction_pointer());
                #[cfg(feature = "cli")]
                native::omit(|| outln!());
                #[cfg(not(feature = "cli"))]
                outln!();
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    /// A trap frame names no process, so its user-mode program counter is
    /// resolved and unwound in the selected address space, which need not be
    /// the one the thread ran in. Say so when nothing there covers it.
    fn warn_if_user_frame_is_out_of_view(&self, pc: u64) {
        let target = &self.ctx.target;
        if pc >> 63 != 0 {
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
    let mut registers = HashMap::new();
    const AMD64_NAMES: [&str; 18] = [
        "rip", "rsp", "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "eflags",
    ];
    const ARM64_NAMES: [&str; 36] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30", "sp", "pc", "cpsr", "fp", "lr",
    ];
    let names = if frame.is_arm64() {
        &ARM64_NAMES[..]
    } else {
        &AMD64_NAMES[..]
    };
    for name in names {
        if let Some(value) = saved.get(name) {
            registers.insert(name.to_string(), value);
        }
    }
    registers
}

fn print_exception_record(address: u64, record: &ExceptionRecord) {
    if address != 0 {
        outln!("ExceptionRecord {}", ui::addr(address));
    } else {
        outln!("ExceptionRecord (current)");
    }
    outln!(
        "  ExceptionCode: {:08x} ({})",
        record.code,
        exception_code_name(record.code)
    );
    outln!("  ExceptionFlags: {:08x}", record.flags);
    outln!("  ExceptionRecord: {}", ui::addr(record.nested));
    outln!("  ExceptionAddress: {}", ui::addr(record.address));
    outln!("  NumberParameters: {}", record.parameters.len());
    for (index, value) in record.parameters.iter().enumerate() {
        outln!("  Parameter[{}]: {}", index, ui::addr(*value));
    }
    outln!();
}

/// `r`'s text: the general-purpose grid, then the control and segment
/// registers.
fn print_register_grid(register_map: &RegisterMap, regs: &[u8], arch: Arch) {
    print_registers(register_map, regs, None, false);
    // Control registers match the GP-register cluster's
    // styling; segment selectors are 16-bit, so render
    // them as 4 digits rather than padding to 64-bit
    let read_cr = |name: &str| -> String {
        register_map
            .read_u64(name, regs)
            .map(ui::addr)
            .unwrap_or_else(|_| "N/A".to_string())
    };
    let read_seg = |name: &str| -> String {
        register_map
            .read_u64(name, regs)
            .map(|v| format!("{:04x}", v))
            .unwrap_or_else(|_| "N/A".to_string())
    };

    outln!();
    // The ARM64 maps answer `cr3` with TTBR1_EL1, the kernel's root.
    if arch == Arch::Arm64 {
        outln!("  ttbr0 {}   ttbr1 {}", read_cr("ttbr0"), read_cr("cr3"));
        outln!("  esr   {}   far   {}", read_cr("esr"), read_cr("far"));
        outln!();
        return;
    }
    outln!(
        "  cr0 {}   cr2 {}   cr3 {}",
        read_cr("cr0"),
        read_cr("cr2"),
        read_cr("cr3")
    );
    outln!("  cr4 {}   cr8 {}", read_cr("cr4"), read_cr("cr8"));
    outln!();

    outln!(
        "  cs  {}   ds  {}   es  {}",
        read_seg("cs"),
        read_seg("ds"),
        read_seg("es")
    );
    outln!(
        "  fs  {}   gs  {}   ss  {}",
        read_seg("fs"),
        read_seg("gs"),
        read_seg("ss")
    );
    outln!();
}

pub fn print_indexed_stacktrace(
    trace: &RecoveredStackTrace,
    display_limit: usize,
    frame_offset: usize,
    columns: StackColumns,
    selected_index: Option<usize>,
) {
    let mut previous_sp = None;
    for (index, recovered) in trace.frames.iter().take(display_limit).enumerate() {
        let frame = &recovered.frame;
        let global_index = frame_offset + index;
        let marker = if selected_index == Some(global_index) {
            "*"
        } else {
            " "
        };
        let symbol = if frame.symbol.starts_with("0x") {
            frame.symbol.clone()
        } else if frame.inline {
            format!("{} {}", ui::symbol(&frame.symbol), inline_tag())
        } else {
            ui::symbol(&frame.symbol)
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
            .map(|location| format!("  [{}:{}]", location.file, location.line))
            .unwrap_or_default();
        outln!(
            "{}{:02} {}{}  {}{}{}",
            marker,
            global_index,
            frame_size,
            ui::addr(frame.sp),
            ui::addr(frame.ip),
            if symbol.is_empty() {
                "".to_string()
            } else {
                format!("  {symbol}")
            },
            format!("{provenance}{location}")
        );
    }
    let hidden = trace.frames.len().saturating_sub(display_limit) + trace.truncated;
    if hidden > 0 {
        outln!("{}", format!("... {} more frames", hidden).bright_black());
    }
}

/// `.fnent` in WinDbg's order: the entry, its unwind info, then each chained
/// parent's.
fn print_function_entry(detail: &FunctionEntryDetail) {
    let base = detail.image_base;
    let va = |rva: u32| ui::addr(base.wrapping_add(u64::from(rva)));
    let print_handler = |handler: &Option<HandlerDetail>| {
        if let Some(handler) = handler {
            outln!(
                "    handler {} {}, data at {}",
                va(handler.rva),
                ui::symbol(&handler.symbol),
                va(handler.data_rva)
            );
        }
    };
    for (index, entry) in detail.entries.iter().enumerate() {
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
        outln!();
        outln!(
            "  BeginAddress      = {:08x}  {}",
            entry.begin,
            va(entry.begin)
        );
        outln!("  EndAddress        = {:08x}  {}", entry.end, va(entry.end));
        if matches!(
            entry.unwind,
            Some(UnwindDetail::Arm64(Arm64UnwindDetail::Packed { .. }))
        ) {
            outln!("  UnwindData        = {:08x}  (packed)", entry.unwind_data);
        } else {
            outln!(
                "  UnwindInfoAddress = {:08x}  {}",
                entry.unwind_data,
                va(entry.unwind_data)
            );
        }
        outln!();
        match &entry.unwind {
            None => outln!("  unwind info unreadable"),
            Some(UnwindDetail::Amd64(info)) => {
                outln!(
                    "  Unwind info at {}, {} bytes",
                    va(entry.unwind_data),
                    info.size
                );
                let flag_names: Vec<&str> = [(1, "EHANDLER"), (2, "UHANDLER"), (4, "CHAININFO")]
                    .into_iter()
                    .filter(|(bit, _)| info.flags & bit != 0)
                    .map(|(_, name)| name)
                    .collect();
                outln!(
                    "    version {}, flags {:#x}{}, prolog {:#x}, codes {}",
                    info.version,
                    info.flags,
                    if flag_names.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", flag_names.join(" "))
                    },
                    info.prolog_size,
                    info.code_count
                );
                if let Some(register) = info.frame_register {
                    outln!(
                        "    frame register {register}, frame offset {:#x}",
                        info.frame_offset
                    );
                }
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
                print_handler(&info.handler);
            }
            Some(UnwindDetail::Arm64(Arm64UnwindDetail::Packed {
                flag,
                reg_f,
                reg_i,
                homes_arguments,
                cr,
                frame_size,
                codes,
            })) => {
                outln!(
                    "  Packed unwind data: flag {flag}, RegF {reg_f}, RegI {reg_i}, H {}, CR {cr}, frame size {frame_size:#x}",
                    u8::from(*homes_arguments)
                );
                outln!("    prolog codes:");
                print_arm64_codes(codes);
            }
            Some(UnwindDetail::Arm64(Arm64UnwindDetail::Xdata {
                version,
                exception_data,
                epilog_in_header,
                epilog_count,
                code_words,
                scopes,
                codes,
                handler,
                size,
            })) => {
                outln!("  Unwind info at {}, {size} bytes", va(entry.unwind_data));
                outln!(
                    "    version {version}, X {}, E {}, epilog {} {epilog_count}, code words {code_words}",
                    u8::from(*exception_data),
                    u8::from(*epilog_in_header),
                    if *epilog_in_header {
                        "code index"
                    } else {
                        "count"
                    }
                );
                for (start, first_code) in scopes {
                    outln!("    epilog at +{start:#x}, codes from index {first_code:#x}");
                }
                print_arm64_codes(codes);
                print_handler(handler);
            }
        }
        outln!();
    }
    if let Some(reason) = &detail.incomplete {
        outln!("{}\n", ui::muted(reason));
    }
}

fn print_arm64_codes(codes: &[Arm64CodeDetail]) {
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
