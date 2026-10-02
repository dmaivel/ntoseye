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
use crate::target::{DiagnosticValue, ServedVp, Target};
use crate::types::{Arch, VirtAddr};
use crate::ui;

use super::diagnostics::{diagnostic_addr, diagnostic_cell, diagnostic_hex};

const IDT_VECTOR_COUNT: u16 = 256;
const MSR_SWITCH: &str = "/p";
const MAX_PROCESSOR_SELECTION: usize = 256;

/// What a `~` command names: one processor by number, one vCPU by the id
/// `~` lists, or every processor (`~*`).
enum TildeSelector {
    Number(u64),
    Id(String),
    All,
}

repl_command! {
    cmd_rdmsr;
    names: ["rdmsr"],
    usage: "rdmsr [/p <processor>] <msr>",
    summary: "Read a model-specific register from a halted processor.",
    details: "Reads one model-specific register on the selected processor, or on another processor that you select with /p. The dump and memory backends show that MSR access is unavailable.",
    completion: [None, Expression, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_wrmsr;
    names: ["wrmsr"],
    usage: "wrmsr <msr> <value>",
    summary: "Write a model-specific register on the current processor.",
    details: "Writes one model-specific register on the current processor. You can use a common IA32_* name instead of the numeric MSR.",
    completion: [Expression, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_pcr;
    names: ["!pcr", "pcr"],
    usage: "!pcr [processor]",
    summary: "Show the main KPCR data of the selected processor.",
    details: "Shows the KPCR and KPRCB addresses, the thread pointers, the descriptor registers, the TSS, and the available IRQL fields. On AMD64 Windows, kernel GS usually points to the KPCR, and backend GS-base registers are optional.",
    completion: Expression,
}

repl_command! {
    cmd_prcb;
    names: ["!prcb", "prcb"],
    usage: "!prcb [processor]",
    summary: "Show the main KPRCB data of the selected processor.",
    details: "Shows the processor number, the thread pointers, the DPC and interrupt counters, and the available ProcessorState metadata of the selected KPRCB.",
    completion: Expression,
}

repl_command! {
    cmd_irql;
    names: ["!irql", "irql"],
    usage: "!irql [processor]",
    summary: "Show the current IRQL of a processor.",
    details: "Shows the current IRQL and the Windows level name of the selected processor. At a KD break-in, this is the IRQL that the debugger sees, which can be different from the level before the break-in.",
    completion: Expression,
}

repl_command! {
    cmd_idt;
    names: ["!idt", "idt"],
    usage: "!idt [vector]",
    summary: "Decode one IDT entry or the bounded 256-entry IDT.",
    details: "Shows one IDT vector or all 256 entries, with the handler, selector, gate type, DPL, presence, non-nt hooks, and KiIsrThunk chain hints of each entry.",
    completion: Expression,
}

repl_command! {
    cmd_gdt;
    names: ["!gdt", "gdt"],
    usage: "!gdt",
    summary: "Decode the bounded GDT of the current processor.",
    details: "Shows the bounded GDT entries of the selected processor, with the base, limit, privilege, mode, and presence of each entry.",
}

repl_command! {
    cmd_dg;
    names: ["dg"],
    usage: "dg <first-selector> [last-selector]",
    summary: "Decode segment selectors from the GDT of the current processor.",
    details: "Shows each selector from the first to the last, in steps of 8 as WinDbg does. For each selector, it shows the descriptor base, limit, type, privilege level, size (Bg/Nb), granularity (Pg/By), presence (P/NP), long mode (Lo/Nl), and attribute flags. If a selector refers to an LDT (bit 2 set), dg reports this and does not decode the selector. 64-bit Windows has no LDT.",
    completion: [Expression, Expression],
}

repl_command! {
    cmd_cpuinfo;
    names: ["!cpuinfo", "cpuinfo"],
    usage: "!cpuinfo",
    summary: "Show processor identification, speed, and feature bits.",
    details: "Shows the processor number, vendor, family, model, stepping, speed, and feature bits if they are available. For a field that is not available, ntoseye uses the triage-dump metadata.",
}

repl_command! {
    cmd_vcpus();
    names: ["~", "vcpus"],
    usage: "~",
    summary: "List vCPU contexts and their RIP values.",
    details: "`~Ns` selects processor N (zero-based), and `t` and `p` then step that processor. The vCPU id that the list shows also works in place of N (`~p01.03s`, `~p01.03k`). Over `kd` and `kdnet` on an AMD64 target, the other processors run during the step, as in WinDbg. On an ARM64 target, only the processor that stopped the target can step over `kd` or `kdnet`. If a vCPU halted in the Windows hypervisor (VBS), the list also shows where its VTL0 execution stopped, from the saved state of the hypervisor. `~Ns` on that vCPU selects the VTL0 context, and `.cxr` selects the hypervisor registers. A vCPU stopped on the hypervisor's VM-exit entry from outside shows its saved state as `(may be one exit behind)` and keeps the hypervisor registers: KVM writes that state when it enters the hypervisor, so it can still describe the previous exit. A breakpoint on the entry fires after that write, so a vCPU stopped on one shows the current exit.",
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
        diagnostic_addr(&detail.kpcr),
        ui::addr(detail.kprcb.0)
    );
    outln!(
        "  {:<20}: {}",
        "KdVersionBlock",
        diagnostic_addr(&detail.kd_version_block)
    );
    outln!(
        "  {:<20}: {}",
        "CurrentPrcb",
        diagnostic_addr(&detail.current_prcb)
    );
    outln!("  {:<20}: {}", "Irql", render_decimal(&detail.irql));
    outln!("  {:<20}: {}", "Self", diagnostic_addr(&detail.self_pcr));
    outln!("  KPRCB fields:");
    outln!(
        "  {:<20}: {}",
        "CurrentThread",
        diagnostic_addr(&detail.current_thread)
    );
    outln!(
        "  {:<20}: {}",
        "NextThread",
        diagnostic_addr(&detail.next_thread)
    );
    outln!(
        "  {:<20}: {}",
        "IdleThread",
        diagnostic_addr(&detail.idle_thread)
    );
    outln!("  {:<20}: {}", "IDTR", render_descriptor(&detail.idtr));
    outln!("  {:<20}: {}", "GDTR", render_descriptor(&detail.gdtr));
    outln!("  {:<20}: {}", "TssBase", diagnostic_addr(&detail.tss_base));
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
        diagnostic_addr(&value.context_frame)
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
        diagnostic_addr(&detail.current_thread)
    );
    outln!(
        "  {:<20}: {}",
        "NextThread",
        diagnostic_addr(&detail.next_thread)
    );
    outln!(
        "  {:<20}: {}",
        "IdleThread",
        diagnostic_addr(&detail.idle_thread)
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
    let ist = diagnostic_cell(&detail.ist);
    let gate_name = diagnostic_cell(&detail.gate_name);
    let dpl = diagnostic_cell(&detail.dpl);
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
    let base = diagnostic_addr(&detail.base);
    let limit = diagnostic_hex(&detail.limit);
    let type_code = diagnostic_hex(&detail.type_code);
    let kind = diagnostic_cell(&detail.descriptor_kind);
    let dpl = diagnostic_cell(&detail.dpl);
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

/// WinDbg's name for a descriptor type: code and data segments by their
/// access bits, system descriptors by their 64-bit-mode meaning.
fn segment_type_name(system: bool, type_code: u8) -> String {
    if system {
        return match type_code {
            0x2 => "LDT",
            0x9 => "TSS64 Avl",
            0xb => "TSS64 Busy",
            0xc => "CallGate64",
            0xe => "IntGate64",
            0xf => "TrapGate64",
            _ => "<Reserved>",
        }
        .to_string();
    }
    let mut name = if type_code & 0x8 != 0 {
        let access = if type_code & 0x2 != 0 { "RE" } else { "EO" };
        let conforming = if type_code & 0x4 != 0 { " Co" } else { "" };
        format!("Code {access}{conforming}")
    } else {
        let access = if type_code & 0x2 != 0 { "RW" } else { "RO" };
        let expand_down = if type_code & 0x4 != 0 { " Ed" } else { "" };
        format!("Data {access}{expand_down}")
    };
    if type_code & 0x1 != 0 {
        name.push_str(" Ac");
    }
    name
}

/// `dg`'s table, in WinDbg's columns.
fn print_selectors(detail: &GdtDetail, selectors: impl Iterator<Item = u16>) {
    fn got<T: Clone>(value: &DiagnosticValue<T>) -> Option<T> {
        match value {
            DiagnosticValue::Available(value) => Some(value.clone()),
            DiagnosticValue::Unavailable(_) => None,
        }
    }
    outln!("{:50}P Si Gr Pr Lo", "");
    outln!(
        "Sel  {:<16} {:<16} {:<10} l ze an es ng Flags",
        "Base",
        "Limit",
        "Type"
    );
    outln!(
        "---- {} {} {} - -- -- -- -- --------",
        "-".repeat(16),
        "-".repeat(16),
        "-".repeat(10)
    );
    for selector in selectors {
        let index = u64::from(selector >> 3);
        let row = if selector & 0x4 != 0 {
            "LDT selector; 64-bit Windows has no LDT".to_string()
        } else if let Some(entry) = detail.entries.iter().find(|entry| entry.index == index) {
            match (got(&entry.raw), got(&entry.type_code), got(&entry.limit)) {
                (Some(raw), Some(type_code), Some(limit)) => {
                    let system = got(&entry.descriptor_kind).as_deref() == Some("system");
                    let flag = |value: &DiagnosticValue<bool>, set: &'static str, clear| {
                        if got(value) == Some(true) { set } else { clear }
                    };
                    format!(
                        "{} {limit:016x} {:<10} {} {} {} {} {} {:08x}",
                        got(&entry.base)
                            .map_or_else(|| "?".repeat(16), |base| format!("{:016x}", base.0)),
                        segment_type_name(system, type_code),
                        got(&entry.dpl).unwrap_or(0),
                        flag(&entry.default_size, "Bg", "Nb"),
                        flag(&entry.granularity, "Pg", "By"),
                        flag(&entry.present, "P ", "Np"),
                        flag(&entry.long_mode, "Lo", "Nl"),
                        // Access byte, then the G/D/L/AVL nibble above it.
                        ((raw >> 40) & 0xff) | (((raw >> 52) & 0xf) << 8)
                    )
                }
                _ => match &entry.raw {
                    DiagnosticValue::Unavailable(error) => format!("<unreadable: {error}>"),
                    DiagnosticValue::Available(_) => "<undecodable>".to_string(),
                },
            }
        } else if index >= detail.entry_count {
            "beyond the GDT limit".to_string()
        } else if detail.entries.iter().any(|entry| {
            entry.index + 1 == index && got(&entry.descriptor_kind).as_deref() == Some("system")
        }) {
            "upper half of the system descriptor before it".to_string()
        } else {
            "past the entries read".to_string()
        };
        outln!("{selector:04x} {row}");
    }
    outln!();
}

fn print_cpuinfo(detail: &CpuInfoDetail) {
    if detail.source == "triage-dump PRCB metadata" {
        outln!("CPU information from triage-dump PRCB metadata");
        outln!("  processor number    : {}", detail.processor);
        outln!(
            "  vendor              : {}",
            diagnostic_cell(&detail.vendor)
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
        diagnostic_addr(&detail.kprcb)
    );
    outln!(
        "  vendor              : {}",
        diagnostic_cell(&detail.vendor)
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

    fn cmd_dg(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let first_arg = require_arg!(invocation, 0, "dg");
        let selector = |arg: &str| match self.eval_or_report(arg)? {
            VirtAddr(value) if value <= 0xffff => Some(value as u16),
            _ => {
                error!("'{arg}' is not a 16-bit selector");
                None
            }
        };
        let Some(first) = selector(first_arg) else {
            return Ok(());
        };
        let Some(last) = invocation.arg(1).map_or(Some(first), selector) else {
            return Ok(());
        };
        if last < first {
            error!("the last selector {last:#x} is below the first {first:#x}");
            return Ok(());
        }
        if self.ctx.target.arch() == Arch::Arm64 {
            error!("dg is not defined on ARM64 targets");
            return Ok(());
        }
        let processor = match parse_processor(self, None) {
            Ok(processor) => processor,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let detail = match self.ctx.inspect_gdt(processor) {
            Ok(detail) => detail,
            Err(error) => {
                error!("GDTR unavailable: {error}");
                return Ok(());
            }
        };
        print_selectors(&detail, (first..=last).step_by(8));
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
        // A processor is named by its number or by the vCPU id `~` lists
        // (`p01.03`): hex digits and dots after the `p`, which no action
        // letter is.
        let (selector, suffix) = if let Some(rest) = body.strip_prefix('*') {
            (TildeSelector::All, rest)
        } else if body.starts_with(['p', 'P']) {
            let length = 1 + body[1..]
                .chars()
                .take_while(|ch| ch.is_ascii_hexdigit() || *ch == '.')
                .count();
            (
                TildeSelector::Id(body[..length].to_string()),
                &body[length..],
            )
        } else {
            let digits = body.chars().take_while(|ch| ch.is_ascii_digit()).count();
            if digits == 0 {
                error!(
                    "invalid processor selector '{}'; expected ~, ~N[s|k|r], ~<vCPU id>[s|k|r], or ~*k",
                    line
                );
                return Ok(Flow::Continue);
            }
            let selector =
                match Expr::eval_with_radix(&body[..digits], &self.ctx.target, self.radix) {
                    Ok(value) => TildeSelector::Number(value.0),
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
                "unsupported processor command '{}{}'; expected ~, ~N[s|k|r], ~<vCPU id>[s|k|r], or ~*k",
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
        let selected = match selector {
            TildeSelector::Number(number) => {
                if usize::try_from(number).map_or(true, |number| number >= ids.len()) {
                    error!("processor {} out of range", number);
                    return Ok(Flow::Continue);
                }
                resolve(number).into_iter().collect::<Vec<_>>()
            }
            TildeSelector::Id(wanted) => {
                let Some(id) = ids.iter().find(|id| id.eq_ignore_ascii_case(&wanted)) else {
                    error!("no vCPU {} (the vCPUs are {})", wanted, ids.join(", "));
                    return Ok(Flow::Continue);
                };
                vec![id.clone()]
            }
            TildeSelector::All => ids
                .iter()
                .take(MAX_PROCESSOR_SELECTION)
                .cloned()
                .collect::<Vec<_>>(),
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
            self.caches.refresh_symbol_context(&self.ctx.target);
            if let Err(error) = self.dispatch_line(if action == 'k' { "k" } else { "r" }) {
                error!("processor {} command failed: {}", id, error);
            }
        }
        if let Err(error) = self.ctx.set_current_thread(&original) {
            error!("failed to restore processor {}: {}", original, error);
        } else {
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

        // Where the Symbol column starts: each column is as wide as its
        // widest cell, plus two spaces. The lines below a vCPU wrap from
        // there, after their three-column tree glyph.
        let widest = |header: &str, cells: &mut dyn Iterator<Item = usize>| {
            cells.fold(header.len(), usize::max) + 2
        };
        let symbol_column = widest(
            "vCPU",
            &mut vcpus.iter().map(|vcpu| vcpu.id.chars().count()),
        ) + widest(
            "RIP",
            &mut vcpus.iter().map(|vcpu| match vcpu.rip {
                Some(_) => 16,
                None => "unavailable".len(),
            }),
        ) + widest(
            "Context",
            &mut vcpus.iter().map(|vcpu| vcpu.context.chars().count()),
        );

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
            // Below a vCPU in the hypervisor: where NT left off, and the
            // guest VP the processor serves, as the stop header has them.
            let mut children: Vec<String> = vcpu
                .saved_vtl
                .iter()
                .filter(|saved| saved.summarized())
                .map(|saved| format!("saved {}", saved.describe()))
                .collect();
            if let Some(served) = &vcpu.serving {
                children.push(served_vp_lines(served, symbol_column + 3));
            }
            for line in event_children_lines("", &children) {
                builder.push_record(vec![String::new(), String::new(), String::new(), line]);
            }
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
        self.caches.refresh_symbol_context(&self.ctx.target);
        outln!("switched to vCPU {}\n", self.ctx.current_thread);

        Ok(())
    }
}

/// The guest VP a vCPU in the hypervisor serves, as a line below it in `~`:
/// `serving partition 0x6 VP 3  VTL0 00007dbffd31f313, last exit VMCALL`,
/// with the hypercall of a VMCALL exit on a tree line below, as `.vtlcxr`
/// shows it. A line too long for the terminal from column `col` puts the
/// last exit on a line of its own, under where the VP left off.
fn served_vp_lines(served: &ServedVp, col: usize) -> String {
    let head = format!("serving {}  ", served.label());
    let place = served.place();
    let mut text = match served.last_exit() {
        Some(exit) if wrap_prose(&format!("{head}{place}, {exit}"), col).len() > 1 => {
            format!("{head}{place}\n{}{exit}", " ".repeat(head.len()))
        }
        Some(exit) => format!("{head}{place}, {exit}"),
        None => format!("{head}{place}"),
    };
    if let Some(detail) = served.exit_detail() {
        for line in event_children_lines("", &[detail]) {
            text.push('\n');
            text.push_str(&line);
        }
    }
    text
}
