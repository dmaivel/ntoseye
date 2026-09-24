use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use tabled::builder::Builder;

use crate::cpu_state;
use crate::dbg_backend::{DebugCapability, processor_index_from_backend_thread_id};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::*;
use crate::target::cpu::{
    CpuInfoDetail, CpuTriageInfo, DescriptorDetail, GdtDetail, GdtEntryDetail, IdtDetail,
    IdtEntryDetail, IrqlDetail, PcrDetail, PrcbDetail, ProcessorStateDetail,
    SpecialRegistersDetail, msr_name, parse_msr_name,
};
use crate::target::{DiagnosticValue, Target};
use crate::types::{Arch, VirtAddr};
use crate::ui;

const IDT_VECTOR_COUNT: u16 = 256;
const MSR_SWITCH: &str = "/p";
const MAX_PROCESSOR_SELECTION: usize = 256;

repl_command! {
    cmd_rdmsr;
    names: ["rdmsr"],
    usage: "rdmsr [/p <processor>] <msr>",
    summary: "Read a model-specific register from a halted processor.",
    details: "Reads one model-specific register on the selected processor. Use /p to select another processor; dump and memory backends report MSR access as unavailable.",
    completion: [None, Expression, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_wrmsr;
    names: ["wrmsr"],
    usage: "wrmsr <msr> <value>",
    summary: "Write a model-specific register on the current processor.",
    details: "Writes one model-specific register on the current processor. Common IA32_* names are accepted in place of the numeric MSR.",
    completion: [Expression, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_pcr;
    names: ["!pcr", "pcr"],
    usage: "!pcr [processor]",
    summary: "Display the selected processor's KPCR essentials.",
    details: "Shows KPCR and KPRCB addresses, thread pointers, descriptor registers, TSS, and available IRQL fields. On AMD64 Windows, kernel GS normally addresses the KPCR; backend GS-base registers are optional.",
    completion: Expression,
}

repl_command! {
    cmd_prcb;
    names: ["!prcb", "prcb"],
    usage: "!prcb [processor]",
    summary: "Display the selected processor's KPRCB essentials.",
    details: "Shows the selected KPRCB's processor number, thread pointers, DPC and interrupt counters, and available ProcessorState metadata.",
    completion: Expression,
}

repl_command! {
    cmd_irql;
    names: ["!irql", "irql"],
    usage: "!irql [processor]",
    summary: "Display the current IRQL for a processor.",
    details: "Shows the selected processor's current IRQL and Windows level name. At a KD break-in, this is the debugger's observed IRQL and may differ from the level before the break-in.",
    completion: Expression,
}

repl_command! {
    cmd_idt;
    names: ["!idt", "idt"],
    usage: "!idt [vector]",
    summary: "Decode one IDT entry or the bounded 256-entry IDT.",
    details: "Shows one IDT vector or all 256 entries with handler, selector, gate type, DPL, presence, non-nt hooks, and KiIsrThunk chain hints.",
    completion: Expression,
}

repl_command! {
    cmd_gdt;
    names: ["!gdt", "gdt"],
    usage: "!gdt",
    summary: "Decode the current processor's bounded GDT.",
    details: "Shows the selected processor's bounded GDT entries with base, limit, privilege, mode, and presence.",
}

repl_command! {
    cmd_cpuinfo;
    names: ["!cpuinfo", "cpuinfo"],
    usage: "!cpuinfo",
    summary: "Display vendor, family, model, stepping, speed, and feature bits.",
    details: "Shows processor number, vendor, family, model and stepping, speed, and feature bits when available; triage-dump metadata fills unavailable fields.",
}

repl_command! {
    cmd_vcpus();
    names: ["~", "vcpus"],
    usage: "~",
    summary: "List vCPU contexts and their RIP values.",
    run_state: Halted,
}

repl_command! {
    cmd_vcpu;
    names: ["vcpu"],
    usage: "vcpu <id>",
    summary: "Switch to a different vCPU context.",
    completion: Vcpu,
    run_state: Halted,
}

fn current_processor(state: &ReplState<'_>) -> u16 {
    processor_index_from_backend_thread_id(&state.ctx.current_thread).unwrap_or(0)
}

fn processor_count(state: &mut ReplState<'_>) -> u16 {
    if let Ok(count) = cpu_state::processor_count(&state.ctx.target) {
        return count.max(1);
    }
    // cpu_state intentionally only depends on Target. A live backend is the
    // second source of truth when KeNumberProcessors is absent from a dump.
    state
        .ctx
        .backend
        .thread_list()
        .ok()
        .map(|threads| {
            threads
                .len()
                .clamp(1, usize::from(cpu_state::MAX_PROCESSORS)) as u16
        })
        .unwrap_or(1)
}

fn parse_processor(state: &mut ReplState<'_>, text: Option<&str>) -> Result<u16> {
    let count = processor_count(state);
    let processor = match text {
        Some(text) => {
            let value = Expr::eval_with_radix(text, &state.ctx.target, state.radix)?.0;
            u16::try_from(value).map_err(|_| {
                Error::DebugInfo(format!(
                    "processor index {value:#x} does not fit in 16 bits"
                ))
            })?
        }
        None => current_processor(state),
    };
    if processor >= count {
        return Err(Error::DebugInfo(format!(
            "processor {processor} out of range (target has {count} processor(s))"
        )));
    }
    Ok(processor)
}

fn command_capability(state: &ReplState<'_>, capability: DebugCapability) -> bool {
    let capabilities = state.ctx.backend.capabilities();
    if capabilities
        .iter()
        .any(|entry| entry.capability == capability && entry.supported)
    {
        true
    } else {
        if capability == DebugCapability::Msr {
            error!(
                "backend does not support model-specific registers (MSR access is live-backend only)"
            );
        } else {
            error!("backend does not support {}", capability.label());
        }
        false
    }
}

fn render_diagnostic<T>(value: &DiagnosticValue<T>, render: impl FnOnce(&T) -> String) -> String {
    match value {
        DiagnosticValue::Available(value) => render(value),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn render_address(value: &DiagnosticValue<VirtAddr>) -> String {
    render_diagnostic(value, |value| ui::addr(value.0).to_string())
}

fn render_decimal(value: &DiagnosticValue<u64>) -> String {
    render_diagnostic(value, |value| format!("{value} ({value:#x})"))
}

fn render_descriptor(value: &DiagnosticValue<DescriptorDetail>) -> String {
    render_diagnostic(value, |value| {
        format!("base {} limit {:#x}", ui::addr(value.base.0), value.limit)
    })
}

fn print_pcr(detail: &PcrDetail) {
    outln!(
        "KPCR for processor {} at {} (KPRCB {})",
        detail.processor,
        render_address(&detail.kpcr),
        ui::addr(detail.kprcb.0)
    );
    outln!(
        "  {:<20}: {}",
        "KdVersionBlock",
        render_address(&detail.kd_version_block)
    );
    outln!(
        "  {:<20}: {}",
        "CurrentPrcb",
        render_address(&detail.current_prcb)
    );
    outln!("  {:<20}: {}", "Irql", render_decimal(&detail.irql));
    outln!("  {:<20}: {}", "Self", render_address(&detail.self_pcr));
    outln!("  KPRCB fields:");
    outln!(
        "  {:<20}: {}",
        "CurrentThread",
        render_address(&detail.current_thread)
    );
    outln!(
        "  {:<20}: {}",
        "NextThread",
        render_address(&detail.next_thread)
    );
    outln!(
        "  {:<20}: {}",
        "IdleThread",
        render_address(&detail.idle_thread)
    );
    outln!("  {:<20}: {}", "IDTR", render_descriptor(&detail.idtr));
    outln!("  {:<20}: {}", "GDTR", render_descriptor(&detail.gdtr));
    outln!("  {:<20}: {}", "TssBase", render_address(&detail.tss_base));
}

fn print_special_registers(value: &SpecialRegistersDetail) {
    outln!(
        "  SpecialRegisters    : {} ({} bytes, {})",
        ui::addr(value.address.0),
        value.size,
        value.name
    );
}

fn print_processor_state(value: &ProcessorStateDetail) {
    outln!(
        "  ProcessorState      : {} ({} bytes, {})",
        ui::addr(value.address.0),
        value.size,
        value.name
    );
    outln!(
        "  {:<20}: {}",
        "ContextFrame",
        render_address(&value.context_frame)
    );
    match &value.special_registers {
        DiagnosticValue::Available(value) => print_special_registers(value),
        DiagnosticValue::Unavailable(error) => {
            outln!("  SpecialRegisters    : <unavailable: {error}>")
        }
    }
}

fn print_prcb(detail: &PrcbDetail) {
    outln!(
        "KPRCB for processor {} at {}",
        detail.processor,
        ui::addr(detail.kprcb.0)
    );
    outln!("  {:<20}: {}", "Number", render_decimal(&detail.number));
    outln!(
        "  {:<20}: {}",
        "CurrentThread",
        render_address(&detail.current_thread)
    );
    outln!(
        "  {:<20}: {}",
        "NextThread",
        render_address(&detail.next_thread)
    );
    outln!(
        "  {:<20}: {}",
        "IdleThread",
        render_address(&detail.idle_thread)
    );
    outln!(
        "  {:<20}: {}",
        "DpcRoutineActive",
        render_decimal(&detail.dpc_routine_active)
    );
    outln!(
        "  {:<20}: {}",
        "InterruptCount",
        render_decimal(&detail.interrupt_count)
    );
    match &detail.processor_state {
        DiagnosticValue::Available(value) => print_processor_state(value),
        DiagnosticValue::Unavailable(error) => {
            outln!("  ProcessorState      : <unavailable: {error}>")
        }
    }
}

fn print_irql(detail: &IrqlDetail) {
    match (&detail.value, &detail.level_name) {
        (DiagnosticValue::Available(value), DiagnosticValue::Available(name)) => {
            outln!("processor {} IRQL {} ({})", detail.processor, value, name);
        }
        (DiagnosticValue::Unavailable(error), _) => {
            error!("current IRQL unavailable: {error}");
        }
        (_, DiagnosticValue::Unavailable(error)) => {
            error!("current IRQL unavailable: {error}");
        }
    }
}

fn print_idt_entry(detail: &IdtEntryDetail) {
    let handler = match &detail.handler {
        DiagnosticValue::Available(handler) => *handler,
        DiagnosticValue::Unavailable(error) => {
            outln!("  {:02x}: <unavailable: {}>", detail.vector, error);
            return;
        }
    };
    let symbol = match &detail.symbol {
        DiagnosticValue::Available(Some(symbol)) => symbol.clone(),
        DiagnosticValue::Available(None) => ui::addr(handler.0).to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    };
    let selector = render_diagnostic(&detail.selector, |selector| format!("{selector:#06x}"));
    let ist = render_diagnostic(&detail.ist, |ist| ist.to_string());
    let gate_name = render_diagnostic(&detail.gate_name, |name| name.clone());
    let dpl = render_diagnostic(&detail.dpl, |dpl| dpl.to_string());
    let present = render_diagnostic(&detail.present, |present| {
        if *present {
            "present".to_string()
        } else {
            "not-present".to_string()
        }
    });
    let hook = matches!(&detail.non_nt_hook, DiagnosticValue::Available(true));
    outln!(
        "  {:02x}: {} sel={} ist={} type={} dpl={} {}{}",
        detail.vector,
        symbol,
        selector,
        ist,
        gate_name,
        dpl,
        present,
        if hook { " [NON-NT HOOK]" } else { "" }
    );
    if let DiagnosticValue::Available(Some(chain)) = &detail.ki_isr_thunk {
        outln!("       chain: {chain}");
    }
}

fn print_idt(detail: &IdtDetail) {
    outln!(
        "IDT processor {} base {} limit {:#x}",
        detail.processor,
        ui::addr(detail.base.0),
        detail.limit
    );
    for entry in &detail.entries {
        print_idt_entry(entry);
    }
}

fn print_gdt_entry(detail: &GdtEntryDetail) {
    match &detail.raw {
        DiagnosticValue::Available(_) => {}
        DiagnosticValue::Unavailable(error) => {
            outln!("  {:>3}: <unavailable: {error}>", detail.index);
            return;
        }
    };
    let base = render_diagnostic(&detail.base, |base| ui::addr(base.0).to_string());
    let limit = render_diagnostic(&detail.limit, |limit| format!("{limit:#x}"));
    let type_code = render_diagnostic(&detail.type_code, |type_code| format!("{type_code:#x}"));
    let kind = render_diagnostic(&detail.descriptor_kind, |kind| kind.clone());
    let dpl = render_diagnostic(&detail.dpl, |dpl| dpl.to_string());
    let present = render_diagnostic(&detail.present, |present| {
        if *present {
            "present".to_string()
        } else {
            "not-present".to_string()
        }
    });
    let long_mode = match &detail.long_mode {
        DiagnosticValue::Available(true) => " L",
        DiagnosticValue::Available(false) => match &detail.default_size {
            DiagnosticValue::Available(true) => " D/B",
            _ => "",
        },
        DiagnosticValue::Unavailable(_) => "",
    };
    let granularity = match &detail.granularity {
        DiagnosticValue::Available(true) => " G",
        _ => "",
    };
    outln!(
        "  {:>3}: base {} limit {} type={} {} dpl={} {}{}{}",
        detail.index,
        base,
        limit,
        type_code,
        kind,
        dpl,
        present,
        long_mode,
        granularity
    );
}

fn print_gdt(detail: &GdtDetail) {
    outln!(
        "GDT processor {} base {} limit {:#x} ({} entries)",
        detail.processor,
        ui::addr(detail.base.0),
        detail.limit,
        detail.entry_count
    );
    for entry in &detail.entries {
        print_gdt_entry(entry);
    }
}

fn print_cpuinfo(detail: &CpuInfoDetail) {
    if detail.source == "triage-dump PRCB metadata" {
        outln!("CPU information from triage-dump PRCB metadata");
        outln!("  processor number    : {}", detail.processor);
        outln!(
            "  vendor              : {}",
            render_diagnostic(&detail.vendor, |value| value.clone())
        );
        outln!("  family              : {}", render_decimal(&detail.family));
        outln!("  model/stepping      : <unavailable>");
        outln!("  speed MHz           : {}", render_decimal(&detail.mhz));
        outln!("  feature bits        : <unavailable>");
        return;
    }
    outln!(
        "CPU information for processor {} (KPRCB {})",
        detail.processor,
        render_address(&detail.kprcb)
    );
    outln!(
        "  vendor              : {}",
        render_diagnostic(&detail.vendor, |value| value.clone())
    );
    outln!(
        "  vendor id           : {}",
        render_decimal(&detail.vendor_id)
    );
    outln!("  family              : {}", render_decimal(&detail.family));
    match (&detail.model, &detail.stepping) {
        (DiagnosticValue::Available(model), DiagnosticValue::Available(stepping)) => outln!(
            "  model/stepping      : model {:#x} stepping {}",
            model,
            stepping
        ),
        (DiagnosticValue::Unavailable(error), _) => {
            outln!("  model/stepping      : <unavailable: {error}>")
        }
        (_, DiagnosticValue::Unavailable(error)) => {
            outln!("  model/stepping      : <unavailable: {error}>")
        }
    }
    outln!("  speed MHz           : {}", render_decimal(&detail.mhz));
    let mut feature_found = false;
    for feature in &detail.feature_bits {
        if let DiagnosticValue::Available(value) = &feature.value {
            feature_found = true;
            outln!("  {:<19}: {}", feature.name, ui::addr(*value));
        }
    }
    if !feature_found {
        outln!("  feature bits        : <unavailable>");
    }
    if let Some(fallback) = detail.triage_fallback.as_ref() {
        print_triage_fallback(fallback);
    }
}

fn print_triage_fallback(detail: &CpuTriageInfo) {
    outln!("CPU information from triage-dump PRCB metadata");
    outln!("  processor number    : {}", detail.processor_number);
    outln!("  vendor              : {}", detail.vendor);
    outln!(
        "  family              : {} ({:#x})",
        detail.family,
        detail.family
    );
    outln!("  model/stepping      : <unavailable>");
    outln!("  speed MHz           : {}", detail.mhz);
    outln!("  feature bits        : <unavailable>");
}

fn parse_msr(state: &ReplState<'_>, text: &str) -> Result<u32> {
    if let Some(msr) = parse_msr_name(text) {
        return Ok(msr);
    }
    let value = Expr::eval_with_radix(text, &state.ctx.target, state.radix)?.0;
    u32::try_from(value)
        .map_err(|_| Error::DebugInfo(format!("MSR {value:#x} does not fit in 32 bits")))
}

fn render_msr_value(target: &Target, value: u64) -> String {
    let raw = ui::addr(value).to_string();
    target
        .symbols
        .format_closest_symbol_for_address(target.kernel_dtb(), VirtAddr(value))
        .map(|symbol| format!("{raw} ({symbol})"))
        .unwrap_or(raw)
}

impl ReplState<'_> {
    fn cmd_rdmsr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !command_capability(self, DebugCapability::Msr) {
            return Ok(());
        }
        let (msr_text, processor_text) = match invocation.argv.as_slice() {
            [msr] => (msr.as_ref(), None),
            [switch, processor, msr] if switch.as_ref().eq_ignore_ascii_case(MSR_SWITCH) => {
                (msr.as_ref(), Some(processor.as_ref()))
            }
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        let processor = match parse_processor(self, processor_text) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let msr = match parse_msr(self, msr_text) {
            Ok(msr) => msr,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.read_msr(processor, msr) {
            Ok(value) => outln!(
                "processor {}  {} ({:#x}) = {}",
                processor,
                msr_name(msr).unwrap_or("MSR"),
                msr,
                render_msr_value(&self.ctx.target, value)
            ),
            Err(error) => error!(
                "failed to read {:#x} on processor {}: {error}",
                msr, processor
            ),
        }
        Ok(())
    }

    fn cmd_wrmsr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !command_capability(self, DebugCapability::Msr) {
            return Ok(());
        }
        if invocation.argv.len() != 2 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let msr = match parse_msr(self, require_arg!(invocation, 0, "wrmsr")) {
            Ok(msr) => msr,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some(VirtAddr(value)) = self.eval_or_report(require_arg!(invocation, 1, "wrmsr"))
        else {
            return Ok(());
        };
        let processor = current_processor(self);
        match self.ctx.write_msr(processor, msr, value) {
            Ok(()) => outln!(
                "processor {}  {} ({:#x}) <- {}",
                processor,
                msr_name(msr).unwrap_or("MSR"),
                msr,
                ui::addr(value)
            ),
            Err(error) => error!(
                "failed to write {:#x} on processor {}: {error}",
                msr, processor
            ),
        }
        Ok(())
    }

    fn cmd_pcr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let processor = match parse_processor(self, invocation.arg(0)) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.inspect_pcr(processor) {
            Ok(detail) => print_pcr(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_prcb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let processor = match parse_processor(self, invocation.arg(0)) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.target.inspect_prcb(processor) {
            Ok(detail) => print_prcb(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_irql(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let processor = match parse_processor(self, invocation.arg(0)) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.target.inspect_irql(processor) {
            Ok(detail) => print_irql(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_idt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        if self.ctx.target.arch() == Arch::Arm64 {
            error!("!idt is not defined on ARM64 targets");
            return Ok(());
        }
        let vector = match invocation.arg(0) {
            Some(text) => match self.eval_or_report(text) {
                Some(value) if value.0 < u64::from(IDT_VECTOR_COUNT) => Some(value.0 as u16),
                Some(value) => {
                    error!("IDT vector {:#x} is outside 0..255", value.0);
                    return Ok(());
                }
                None => return Ok(()),
            },
            None => None,
        };
        let processor = match parse_processor(self, None) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.inspect_idt(processor, vector) {
            Ok(detail) => print_idt(&detail),
            Err(error) => error!("IDTR unavailable: {error}"),
        }
        Ok(())
    }

    fn cmd_gdt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        if self.ctx.target.arch() == Arch::Arm64 {
            error!("!gdt is not defined on ARM64 targets");
            return Ok(());
        }
        let processor = match parse_processor(self, None) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.inspect_gdt(processor) {
            Ok(detail) => print_gdt(&detail),
            Err(error) => error!("GDTR unavailable: {error}"),
        }
        Ok(())
    }

    fn cmd_cpuinfo(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let processor = match parse_processor(self, None) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.target.inspect_cpuinfo(processor) {
            Ok(detail) => print_cpuinfo(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    pub fn cmd_tilde(&mut self, line: &str) -> Result<Flow> {
        let body = line.trim().strip_prefix('~').unwrap_or_default();
        if body.is_empty() {
            self.cmd_vcpus()?;
            return Ok(Flow::Continue);
        }
        let (selector, suffix) = if let Some(rest) = body.strip_prefix('*') {
            (None, rest)
        } else {
            let digits = body.chars().take_while(|ch| ch.is_ascii_digit()).count();
            if digits == 0 {
                error!(
                    "invalid processor selector '{}'; expected ~, ~N[s|k|r], or ~*k",
                    line
                );
                return Ok(Flow::Continue);
            }
            let selector =
                match Expr::eval_with_radix(&body[..digits], &self.ctx.target, self.radix) {
                    Ok(value) => Some(value.0),
                    Err(_) => {
                        error!("processor {} out of range", &body[..digits]);
                        return Ok(Flow::Continue);
                    }
                };
            (selector, &body[digits..])
        };
        let mut actions = suffix.chars();
        let action = actions.next().unwrap_or('s');
        if !matches!(action, 's' | 'k' | 'r') {
            error!("invalid processor action '{}'; expected s, k, or r", action);
            return Ok(Flow::Continue);
        }
        // WinDbg accepts a whole command after the selector (`~*kb`, `~0kv`).
        // Only the three single-letter actions are implemented, so anything
        // trailing must be reported: silently running `~*k` for a pasted
        // `~*kb` answers a question the user did not ask.
        let trailing = actions.as_str();
        if !trailing.is_empty() {
            error!(
                "unsupported processor command '{}{}'; expected ~, ~N[s|k|r], or ~*k",
                action, trailing
            );
            return Ok(Flow::Continue);
        }
        let ids = match self.ctx.backend.thread_list() {
            Ok(ids) => ids,
            Err(error) => {
                error!("failed to list processors: {}", error);
                return Ok(Flow::Continue);
            }
        };
        let resolve = |number: u64| {
            ids.iter()
                .find(|id| processor_index_from_backend_thread_id(id) == u16::try_from(number).ok())
                .cloned()
                .or_else(|| {
                    ids.iter()
                        .find(|id| {
                            id.as_str()
                                .eq_ignore_ascii_case(&format!("p1.{:x}", number.saturating_add(1)))
                        })
                        .cloned()
                })
                .or_else(|| {
                    usize::try_from(number)
                        .ok()
                        .and_then(|index| ids.get(index).cloned())
                })
        };
        let selected = if let Some(number) = selector {
            if usize::try_from(number).map_or(true, |number| number >= ids.len()) {
                error!("processor {} out of range", number);
                return Ok(Flow::Continue);
            }
            resolve(number).into_iter().collect::<Vec<_>>()
        } else {
            ids.iter()
                .take(MAX_PROCESSOR_SELECTION)
                .cloned()
                .collect::<Vec<_>>()
        };
        if selected.is_empty() {
            error!("processor not found");
            return Ok(Flow::Continue);
        }
        let original = self.ctx.current_thread.clone();
        if action == 's' {
            let id = selected[0].clone();
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch processor: {}", error);
            } else {
                self.clear_selected_frame();
                refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &id);
                self.caches.refresh_symbol_context(&self.ctx.target);
                outln!("switched to processor {}\n", id);
            }
            return Ok(Flow::Continue);
        }

        for id in selected {
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch processor {}: {}", id, error);
                continue;
            }
            self.clear_selected_frame();
            refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &id);
            self.caches.refresh_symbol_context(&self.ctx.target);
            if let Err(error) = self.dispatch_line(if action == 'k' { "k" } else { "r" }) {
                error!("processor {} command failed: {}", id, error);
            }
        }
        if let Err(error) = self.ctx.set_current_thread(&original) {
            error!("failed to restore processor {}: {}", original, error);
        } else {
            self.clear_selected_frame();
            refresh_windows_thread_context_for_backend_thread(&mut self.ctx.target, &original);
            self.caches.refresh_symbol_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    fn cmd_vcpus(&mut self) -> Result<()> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.black.bright} {msg}")
                .unwrap(),
        );

        pb.set_message(format!("{}", "Waiting on GDB...".bright_black()));
        pb.enable_steady_tick(Duration::from_millis(100));

        let vcpus = match self.ctx.vcpus() {
            Ok(vcpus) => vcpus,
            Err(e) => {
                pb.finish_and_clear();
                error!("{}", e);
                return Ok(());
            }
        };
        self.caches.refresh_vcpus(self.ctx.backend.as_mut());

        pb.finish_and_clear();

        let mut builder = Builder::default();
        builder.push_record(vec!["vCPU", "RIP", "Context", "Symbol"]);
        for vcpu in vcpus {
            let (rip_cell, symbol_cell) = match vcpu.rip {
                Some(rip) => (
                    ui::addr(rip),
                    vcpu.symbol.unwrap_or_else(|| format!("{rip:#x}")),
                ),
                None => (ui::muted("unavailable"), vcpu.error.unwrap_or_default()),
            };
            builder.push_record(vec![
                vcpu.id.to_string(),
                rip_cell.to_string(),
                vcpu.context.to_string(),
                symbol_cell,
            ]);
        }

        print_padded_table(builder);

        Ok(())
    }

    fn cmd_vcpu(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let requested = require_arg!(invocation, 0, "vcpu");

        let threads = match self.ctx.backend.thread_list() {
            Ok(t) => t,
            Err(e) => {
                error!("failed to get vCPU list: {:?}", e);
                return Ok(());
            }
        };

        let thread_id = threads
            .iter()
            .find(|thread| thread.as_str() == requested)
            .cloned()
            .or_else(|| {
                Expr::eval_with_radix(requested, &self.ctx.target, self.radix)
                    .ok()
                    .and_then(|value| u16::try_from(value.0).ok())
                    .and_then(|number| {
                        threads
                            .iter()
                            .find(|thread| {
                                processor_index_from_backend_thread_id(thread) == Some(number)
                            })
                            .cloned()
                            .or_else(|| threads.get(number as usize).cloned())
                    })
            });
        let Some(thread_id) = thread_id else {
            error!("vCPU '{}' not found (use 'vcpus' to list vCPUs)", requested);
            return Ok(());
        };

        if let Err(e) = self.ctx.set_current_thread(&thread_id) {
            error!("failed to switch vCPU: {:?}", e);
            return Ok(());
        }

        self.clear_selected_frame();

        refresh_windows_thread_context_for_backend_thread(
            &mut self.ctx.target,
            &self.ctx.current_thread,
        );
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!("switched to vCPU {}\n", self.ctx.current_thread);

        Ok(())
    }
}
