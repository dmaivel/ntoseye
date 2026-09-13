use std::collections::HashMap;

use crate::backend::MemoryOps;
use crate::bugchecks::{bugcheck_trap_frame_address, looks_like_kernel_pointer};
use crate::error::Result;
use crate::expr::Expr;
use crate::gdb::RegisterMap;
use crate::kd::{context, context_arm64};
use crate::memory::DTB_IDENTITY;
use crate::target::{SavedThreadRegisters, SelectedFrame, Target};
use crate::trapframe::{KtrapFrame, read_ktrap_frame_at_or_current};
use crate::triage_report::exception_code_name;
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    RecoveredFrame, RecoveredStackTrace, build_stacktrace_with_context,
    build_stacktrace_with_register_values,
};

use crate::repl::*;

const MAX_FRAME_INDEX: usize = 4095;

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
        if self.ctx.target.selected_frame.take().is_some() {
            self.ctx.restore_live_register_cache();
        }
    }

    fn set_selected_frame(&mut self, selected: SelectedFrame) {
        self.ctx.target.registers = Some(selected.registers.clone());
        if let Some(cr3) = selected.registers.get("cr3").copied()
            && cr3 != 0
            && self.ctx.target.guest.is_some()
            && self.ctx.target.kernel_dtb() != DTB_IDENTITY
        {
            self.ctx.target.set_context_dtb_override(cr3);
        }
        self.ctx.target.selected_frame = Some(selected);
    }

    pub fn select_register_values(&mut self, index: usize, registers: HashMap<String, u64>) -> u64 {
        let selected = selected_from_registers(index, registers);
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
            print_sparse_registers(&frame.registers);
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
                    let parsed = match Expr::eval_with_radix(value, &self.ctx.target, self.radix) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            error!("{}", error);
                            return Ok(());
                        }
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
            let Some((recovered, seed)) = self.recovered_live_trace(1)? else {
                return Ok(());
            };
            let Some(frame) = recovered.frames.first() else {
                error!("current frame is unavailable");
                return Ok(());
            };
            let selected = selected_from_recovered(frame, 0, Some(&seed));
            self.print_selected_frame(&selected, show_registers);
            return Ok(());
        };
        if index > MAX_FRAME_INDEX {
            error!("frame index is too large");
            return Ok(());
        }

        let limit = index.saturating_add(1);
        let Some((recovered, seed)) = self.recovered_live_trace(limit)? else {
            return Ok(());
        };
        let Some(frame) = recovered.frames.get(index) else {
            error!("frame {} is unavailable", index);
            return Ok(());
        };
        let selected = selected_from_recovered(frame, index, Some(&seed));
        self.set_selected_frame(selected.clone());
        self.print_selected_frame(&selected, show_registers);
        Ok(())
    }

    fn recovered_live_trace(
        &mut self,
        limit: usize,
    ) -> Result<Option<(RecoveredStackTrace, HashMap<String, u64>)>> {
        if let Some(selected) = self.ctx.target.selected_frame.as_ref() {
            let seed = if selected.seed_registers.is_empty() {
                &selected.registers
            } else {
                &selected.seed_registers
            };
            let seed = seed.clone();
            let trace = build_stacktrace_with_register_values(
                &self.ctx.target,
                &self.ctx.register_map,
                &seed,
                limit,
            );
            return Ok(Some((trace, seed)));
        }
        if self.ctx.parked_windows_thread().is_some() {
            error!("frame selection requires a live register context; use `vcpu <id>`");
            return Ok(None);
        }
        let registers = match self.ctx.read_registers() {
            Ok(registers) => registers,
            Err(error) => {
                error!("failed to read registers: {}", error);
                return Ok(None);
            }
        };
        let seed = self.ctx.register_map.to_hashmap(&registers);
        let trace = build_stacktrace_with_context(
            &self.ctx.target,
            &self.ctx.register_map,
            &registers,
            limit,
        );
        Ok(Some((trace, seed)))
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
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let Some(registers) = read_context_at(&self.ctx.target, address) else {
            error!("could not read a CONTEXT at {}", ui::addr(address.0));
            return Ok(());
        };
        let selected = selected_from_registers(0, registers);
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
                    let selected = selected_from_registers(0, registers);
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
            if let Some(registers) = read_context_at(&self.ctx.target, VirtAddr(address)) {
                let selected = selected_from_registers(0, registers);
                self.set_selected_frame(selected.clone());
                outln!("exception context {}", ui::addr(address));
                self.print_selected_frame(&selected, false);
                return Ok(());
            }
            error!("could not read exception context at {}", ui::addr(address));
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
            let selected = selected_from_registers(0, registers);
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
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let Some(record) = read_exception_record(&self.ctx.target, address) else {
            error!(
                "could not read an EXCEPTION_RECORD64 at {}",
                ui::addr(address.0)
            );
            return Ok(());
        };
        print_exception_record(address.0, &record);
        Ok(())
    }

    fn print_current_exception_record(&self) {
        let Some(event) = self.ctx.last_event.as_ref() else {
            if let Some(exception) = self
                .ctx
                .target
                .phys
                .dmp_info()
                .and_then(|info| info.exception.as_ref())
            {
                print_exception_record(
                    0,
                    &ExceptionRecord {
                        code: exception.code,
                        flags: exception.flags,
                        nested: 0,
                        address: exception.address,
                        parameters: exception.parameters.clone(),
                    },
                );
                return;
            }
            error!("no current exception record");
            return;
        };
        let stop = &event.stop;
        let code = stop
            .exception_code
            .or_else(|| stop.bugcheck.as_ref().map(|info| info.parameters[0] as u32));
        let Some(code) = code else {
            error!("no current exception record");
            return;
        };
        let address = stop.exception_address.or(stop.program_counter).unwrap_or(0);
        print_exception_record(
            0,
            &ExceptionRecord {
                code,
                flags: 0,
                nested: 0,
                address,
                parameters: Vec::new(),
            },
        );
    }
}

fn selected_from_recovered(
    frame: &RecoveredFrame,
    index: usize,
    seed_registers: Option<&HashMap<String, u64>>,
) -> SelectedFrame {
    SelectedFrame {
        index,
        ip: frame.frame.ip,
        sp: frame.frame.sp,
        frame_base: frame.frame_base,
        registers: frame.registers.clone(),
        seed_registers: seed_registers
            .filter(|registers| !registers.is_empty())
            .cloned()
            .unwrap_or_else(|| frame.registers.clone()),
    }
}

fn selected_from_registers(index: usize, registers: HashMap<String, u64>) -> SelectedFrame {
    let ip = registers
        .get("rip")
        .copied()
        .or_else(|| registers.get("pc").copied())
        .unwrap_or(0);
    let sp = registers
        .get("rsp")
        .copied()
        .or_else(|| registers.get("sp").copied())
        .unwrap_or(0);
    let seed_registers = registers.clone();
    SelectedFrame {
        index,
        ip,
        sp,
        frame_base: None,
        registers,
        seed_registers,
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

fn print_sparse_registers(registers: &HashMap<String, u64>) {
    let mut names: Vec<_> = registers.keys().collect();
    names.sort();
    outln!("  registers:");
    for name in names {
        outln!("    {:<8} {}", name, ui::addr(registers[name]));
    }
}

fn read_context_at(target: &Target, address: VirtAddr) -> Option<HashMap<String, u64>> {
    let size = match target.arch() {
        Arch::Amd64 => context::CONTEXT_SIZE,
        Arch::Arm64 => context_arm64::CONTEXT_SIZE,
    };
    let mut bytes = vec![0u8; size];
    if !read_context_bytes(target, address, &mut bytes) {
        return None;
    }
    Some(target_register_map(target).to_hashmap(&bytes))
}

fn target_register_map(target: &Target) -> RegisterMap {
    // Context records use the same architecture-specific offsets as the KD
    // register map. This helper is intentionally local so no backend state is
    // mutated while a context is being inspected.
    match target.arch() {
        Arch::Amd64 => context::build_register_map(),
        Arch::Arm64 => context_arm64::build_register_map(),
    }
}

fn read_context_bytes(target: &Target, address: VirtAddr, bytes: &mut [u8]) -> bool {
    target.context_memory().read_bytes(address, bytes).is_ok()
        || target
            .kernel_address_space()
            .read_bytes(address, bytes)
            .is_ok()
}

#[derive(Clone, Debug)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    nested: u64,
    address: u64,
    parameters: Vec<u64>,
}

fn read_exception_record(target: &Target, address: VirtAddr) -> Option<ExceptionRecord> {
    const SIZE: usize = 0x98;
    let mut bytes = vec![0u8; SIZE];
    if !read_context_bytes(target, address, &mut bytes) {
        return None;
    }
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    };
    let code = read_u32(0)?;
    let flags = read_u32(4)?;
    let nested = read_u64(8)?;
    let exception_address = read_u64(16)?;
    let count = usize::try_from(read_u32(24)?).ok()?.min(15);
    let mut parameters = Vec::with_capacity(count);
    for index in 0..count {
        parameters.push(read_u64(32 + index * 8)?);
    }
    Some(ExceptionRecord {
        code,
        flags,
        nested,
        address: exception_address,
        parameters,
    })
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
