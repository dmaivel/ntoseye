use std::collections::HashMap;

use crate::bugchecks::{bugcheck_trap_frame_address, looks_like_kernel_pointer};
use crate::error::Result;
use crate::session::ExceptionRecord;
use crate::target::{SavedThreadRegisters, SelectedFrame};
use crate::trapframe::{KtrapFrame, read_ktrap_frame_at_or_current};
use crate::triage_report::exception_code_name;
use crate::types::VirtAddr;
use crate::unwind::RecoveredStackTrace;

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
            let Some(frame) = recovered.frames.first() else {
                error!("current frame is unavailable");
                return Ok(());
            };
            let selected = SelectedFrame::from_recovered(frame, 0, Some(&seed), live);
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
        let Some(frame) = recovered.frames.get(index) else {
            error!("frame {} is unavailable", index);
            return Ok(());
        };
        let selected = SelectedFrame::from_recovered(frame, index, Some(&seed), live);
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
pub(super) fn print_sparse_registers(
    registers: &HashMap<String, u64>,
    heading: Option<&str>,
    indent: usize,
) {
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
