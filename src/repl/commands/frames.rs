use std::collections::HashMap;

use owo_colors::OwoColorize;

use crate::bugchecks::{bugcheck_trap_frame_address, looks_like_kernel_pointer};
use crate::error::{Error, Result};
use crate::session::ExceptionRecord;
use crate::target::{SavedThreadRegisters, SelectedFrame, lookup_register};
use crate::trapframe::{KtrapFrame, read_ktrap_frame_at_or_current};
use crate::triage_report::exception_code_name;
use crate::types::VirtAddr;
use crate::unwind::{
    RecoveredStackTrace, StackTrace, build_stacktrace_with_context,
    build_stacktrace_with_register_values, format_symbol, resolve_thread_trace_context,
};

use crate::repl::*;

const MAX_FRAME_INDEX: usize = 4095;

/// A recovered trace, the registers its walk was seeded from, and whether
/// that seed is the live vCPU file (a `.cxr`/`.trap` context is not).
type SeededTrace = (RecoveredStackTrace, HashMap<String, u64>, bool);

repl_command! {
    cmd_frame;
    names: [".frame", "frame"],
    usage: ".frame [/r] [N]",
    summary: "Select or display a stack frame.",
    details: "N is a zero-based frame number; /r also displays its recovered registers.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_cxr;
    names: [".cxr"],
    usage: ".cxr [address]",
    summary: "Select a CONTEXT record, or reset the selected context.",
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
    cmd_exr;
    names: [".exr"],
    usage: ".exr <address|-1>",
    summary: "Display an EXCEPTION_RECORD64.",
    completion: Expression,
}

repl_command! {
    cmd_registers;
    names: ["r", "registers"],
    usage: "r [register[=expression]]",
    summary: "Display CPU registers or assign one register.",
    details: "A 128-bit register (xmm0, ARM64 v0) displays at full width; assign its 64-bit halves (xmm0l/xmm0h, v0l/v0h).",
    run_state: Halted,
}

repl_command! {
    cmd_k;
    names: ["kn", "k", "kb", "kp", "kv"],
    usage: "kn|k|kb|kp|kv [count]",
    summary: "Display a stack; kp adds PDB parameter locations and kv provenance.",
    run_state: Halted,
}

repl_command! {
    cmd_trap;
    names: [".trap", "trap"],
    usage: ".trap [address-expression]",
    summary: "Decode and display a _KTRAP_FRAME (defaults to the current thread's saved frame).",
    completion: Expression,
}

impl ReplState<'_> {
    /// Drop any `.frame`/`.cxr`/`.trap` context selection. Called by every
    /// command that changes the execution context (`~Ns`, `vcpu`, `.thread`,
    /// `.process`, run control) so a stale frame never shadows live registers.
    pub fn clear_selected_frame(&mut self) {
        self.ctx.clear_selected_frame();
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

    fn print_selected_frame(&self, frame: &SelectedFrame, show_registers: bool) {
        let symbol = self
            .ctx
            .target
            .closest_symbol_current_context(VirtAddr(frame.ip))
            .unwrap_or_else(|| format!("{:#x}", frame.ip));
        outln!(
            "{} {} {}  {}",
            ui::muted(&format!("#{:02}", frame.index)),
            ui::addr(frame.sp),
            ui::addr(frame.ip),
            ui::symbol(&symbol)
        );
        if let Some(base) = frame.frame_base {
            outln!("  frame base {}", ui::addr(base));
        }
        if show_registers {
            print_sparse_registers(&frame.registers, Some("  registers:"), 4);
        }
        outln!();
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
                self.print_selected_frame(frame, show_registers);
                return Ok(());
            }
            let Some((recovered, seed, live)) = self.recovered_live_trace(1)? else {
                return Ok(());
            };
            let Some(selected) = SelectedFrame::from_recovered(&recovered, 0, Some(&seed), live)
            else {
                error!("current frame is unavailable");
                return Ok(());
            };
            self.print_selected_frame(&selected, show_registers);
            return Ok(());
        };
        if index > MAX_FRAME_INDEX {
            error!("frame index is too large");
            return Ok(());
        }

        let limit = index.saturating_add(1);
        let Some((recovered, seed, live)) = self.recovered_live_trace(limit)? else {
            return Ok(());
        };
        let Some(selected) = SelectedFrame::from_recovered(&recovered, index, Some(&seed), live)
        else {
            error!("frame {} is unavailable", index);
            return Ok(());
        };
        self.set_selected_frame(selected.clone());
        self.print_selected_frame(&selected, show_registers);
        Ok(())
    }

    fn recovered_live_trace(&mut self, limit: usize) -> Result<Option<SeededTrace>> {
        match self.ctx.recovered_live_trace(limit) {
            Ok(trace) => Ok(Some(trace)),
            Err(error) => {
                error!("{}", error);
                Ok(None)
            }
        }
    }

    fn cmd_cxr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            self.clear_selected_frame();
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
        if let Err(e) = self
            .ctx
            .backend
            .set_current_thread(&self.ctx.current_thread)
        {
            error!("failed to select execution context: {:?}", e);
            return Ok(());
        }

        let mut regs = match self.ctx.read_registers() {
            Ok(r) => r,
            Err(e) => {
                error!("failed to read registers: {:?}", e);
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

        print_registers(&self.ctx.register_map, &regs, false);
        // Control registers match the GP-register cluster's
        // styling; segment selectors are 16-bit, so render
        // them as 4 digits rather than padding to 64-bit
        let read_cr = |name: &str| -> String {
            self.ctx
                .register_map
                .read_u64(name, &regs)
                .map(ui::addr)
                .unwrap_or_else(|_| "N/A".to_string())
        };
        let read_seg = |name: &str| -> String {
            self.ctx
                .register_map
                .read_u64(name, &regs)
                .map(|v| format!("{:04x}", v))
                .unwrap_or_else(|_| "N/A".to_string())
        };

        outln!();
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

        Ok(())
    }

    fn print_stack_parameters(&self, trace: &StackTrace, frame_offset: usize) -> Result<()> {
        let mut printed_header = false;
        for (index, frame) in trace.frames.iter().enumerate() {
            let address = VirtAddr(frame.ip);
            let Some(locals) = self.ctx.target.procedure_locals(address)? else {
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
        let frame_limit = match invocation.arg(0) {
            Some(count) => match self.eval_or_report(count) {
                Some(count) => usize::try_from(count.0).unwrap_or(usize::MAX).min(4096),
                None => return Ok(()),
            },
            None => 64,
        };
        if self.ctx.parked_windows_thread().is_some() {
            let trace = match self.ctx.backtrace(frame_limit) {
                Ok(trace) => trace,
                Err(error) => {
                    error!("failed to unwind parked thread stack: {error}");
                    return Ok(());
                }
            };
            if invocation.name.eq_ignore_ascii_case("kv") {
                print_stacktrace_data_with_provenance(&trace, frame_limit, false);
            } else {
                print_stacktrace_data(&trace, frame_limit, false);
            }
            if invocation.name.eq_ignore_ascii_case("kp") {
                self.print_stack_parameters(&trace, 0)?;
            }
            outln!();
            return Ok(());
        }

        let trace = if let Some(selected) = self.ctx.target.selected_frame.as_ref() {
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
                error!("failed to select execution context: {:?}", e);
                return Ok(());
            }
            let regs = match self.ctx.read_registers() {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to read registers: {:?}", e);
                    return Ok(());
                }
            };
            build_stacktrace_with_context(
                &self.ctx.target,
                &self.ctx.register_map,
                &regs,
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
        print_indexed_stacktrace(
            &trace,
            frame_limit,
            offset,
            invocation.name.eq_ignore_ascii_case("kv"),
            self.ctx.target.selected_frame.as_ref().map(|_| offset),
        );
        if invocation.name.eq_ignore_ascii_case("kp") {
            let plain = StackTrace {
                frames: trace
                    .frames
                    .iter()
                    .map(|frame| frame.frame.clone())
                    .collect(),
                truncated: trace.truncated,
            };
            self.print_stack_parameters(&plain, offset)?;
        }
        outln!();

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
            self.clear_selected_frame();
            outln!("selected context reset\n");
            return Ok(());
        }
        match read_ktrap_frame_at_or_current(&self.ctx.target, address) {
            Ok(frame) => {
                // Trap frames are kernel structures; resolve the interrupted
                // rip against the kernel address space like the bugcheck
                // analysis does.
                let trace =
                    resolve_thread_trace_context(&self.ctx.target, self.ctx.target.kernel_dtb());
                let symbol = format_symbol(&self.ctx.target, &trace, frame.instruction_pointer());
                print_ktrap_frame(&frame, Some(&symbol));
                let registers = registers_from_trap_frame(&frame);
                let selected = self.select_register_values(0, registers);
                outln!("selected trap context frame 00 at {}", ui::addr(selected));
                outln!();
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
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

/// Print a recovered (partial) register set sorted by name, one row per
/// register at `indent` columns, under an optional heading line.
fn print_sparse_registers(registers: &HashMap<String, u64>, heading: Option<&str>, indent: usize) {
    let mut names: Vec<_> = registers.keys().collect();
    names.sort();
    if let Some(heading) = heading {
        outln!("{heading}");
    }
    for name in names {
        outln!("{:indent$}{:<8} {}", "", name, ui::addr(registers[name]));
    }
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

fn print_indexed_stacktrace(
    trace: &RecoveredStackTrace,
    display_limit: usize,
    frame_offset: usize,
    show_provenance: bool,
    selected_index: Option<usize>,
) {
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
        } else {
            ui::symbol(&frame.symbol)
        };
        let provenance = if show_provenance {
            format!("  [{}]", frame.source.as_str())
        } else {
            String::new()
        };
        let location = frame
            .source_location
            .as_ref()
            .map(|location| format!("  [{}:{}]", location.file, location.line))
            .unwrap_or_default();
        outln!(
            "{}{:02} {}  {}{}{}",
            marker,
            global_index,
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
