use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use ntoseye_macros::{command, grammar};
use owo_colors::OwoColorize;
use tabled::builder::Builder;

use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::output;
use crate::repl::args::{ArgCursor, ArgCx, ArgError, FromArg};
use crate::repl::*;
use crate::session::Session;
use crate::session::{UserThreadSummary, VcpuInfo};
use crate::target::cpu::{
    CpuInfo, CpuTriageFallback, DescriptorRegister, Gdt, GdtDescriptor, Idt, IdtGate, Irql, Pcr,
    Prcb, Processor, ProcessorStateArea, SpecialRegistersArea, msr_name, parse_msr_name,
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

impl FromArg for Processor {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        let value = cx.eval(text)?.0;
        u16::try_from(value).map(Processor).map_err(|_| {
            ArgError::Message(format!(
                "processor index {value:#x} does not fit in 16 bits"
            ))
        })
    }
}

/// The processor of a command that reads the current vCPU's and takes no
/// processor word (`!idt`, `!gdt`, `!cpuinfo`): `None`, the current one.
#[grammar(usage = "")]
pub fn current_processor(
    _: &mut ArgCx<'_, '_>,
    _: &mut ArgCursor<'_>,
) -> std::result::Result<Option<Processor>, ArgError> {
    Ok(None)
}

/// An MSR by number or by its common `IA32_*` name.
#[derive(Clone, Copy, Debug)]
pub struct Msr(pub u32);

impl FromArg for Msr {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        if let Some(msr) = parse_msr_name(text) {
            return Ok(Msr(msr));
        }
        let value = cx.eval(text)?.0;
        u32::try_from(value)
            .map(Msr)
            .map_err(|_| ArgError::Message(format!("MSR {value:#x} does not fit in 32 bits")))
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

fn render_descriptor(value: &DiagnosticValue<DescriptorRegister>) -> String {
    render_diagnostic(value, |value| {
        format!("base {} limit {:#x}", ui::addr(value.base.0), value.limit)
    })
}

/// An ARM64 `_KPCR` embeds its PRCB, which the first line names, and has
/// no descriptor tables or TSS, so those rows are AMD64's alone.
fn print_pcr(detail: &Pcr, arch: Arch) {
    let amd64 = arch == Arch::Amd64;
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
    if amd64 {
        outln!(
            "  {:<20}: {}",
            "CurrentPrcb",
            diagnostic_addr(&detail.current_prcb)
        );
    }
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
    if amd64 {
        outln!("  {:<20}: {}", "IDTR", render_descriptor(&detail.idtr));
        outln!("  {:<20}: {}", "GDTR", render_descriptor(&detail.gdtr));
        outln!("  {:<20}: {}", "TssBase", diagnostic_addr(&detail.tss_base));
    }
}

fn print_special_registers(value: &SpecialRegistersArea) {
    outln!(
        "  SpecialRegisters    : {} ({} bytes, {})",
        ui::addr(value.address.0),
        value.size,
        value.name
    );
}

fn print_processor_state(value: &ProcessorStateArea) {
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

fn print_prcb(detail: &Prcb) {
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

fn print_irql(detail: &Irql) {
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

fn print_idt_entry(detail: &IdtGate) {
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

fn print_idt(detail: &Idt) {
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

fn print_gdt_entry(detail: &GdtDescriptor) {
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

fn print_gdt(detail: &Gdt) {
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
fn print_selectors(detail: &Gdt, selectors: impl Iterator<Item = u16>) {
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

pub fn print_cpuinfo(detail: &CpuInfo) {
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

fn print_triage_fallback(detail: &CpuTriageFallback) {
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

fn render_msr_value(target: &Target, value: u64) -> String {
    let raw = ui::addr(value).to_string();
    target
        .format_code_address(target.kernel_dtb(), VirtAddr(value))
        .map(|symbol| format!("{raw} ({symbol})"))
        .unwrap_or(raw)
}

/// The processor of `rdmsr /p <processor>`; omitted, the current vCPU's.
#[grammar(usage = "[/p <processor>]", complete = [None, Expression])]
fn msr_processor(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<Processor>, ArgError> {
    if !cursor
        .peek()
        .is_some_and(|word| word.eq_ignore_ascii_case(MSR_SWITCH))
    {
        return Ok(None);
    }
    cursor.word();
    match cursor.word() {
        Some(text) => Processor::from_arg(cx, &text).map(Some),
        None => Err(ArgError::Missing),
    }
}

/// An MSR's value on a processor, as `rdmsr` reads it.
pub struct MsrValue {
    pub processor: u16,
    pub msr: u32,
    pub value: u64,
}

/// Read a model-specific register from a halted processor.
///
/// Reads one model-specific register on the selected processor, or on
/// another processor that you select with /p. The dump and memory backends
/// show that MSR access is unavailable.
#[command(
    names = ["rdmsr"],
    category = "cpu",
    kind = Query,
    target = Machine,
    state = Halted,
    capability = Msr,
    python = none,
)]
fn rdmsr(
    session: &mut Session,
    #[arg(parse = msr_processor)] processor: Option<Processor>,
    msr: Msr,
) -> Result<MsrValue> {
    let processor = session.processor(processor)?;
    let Msr(msr) = msr;
    let value = session.read_msr(processor, msr).map_err(|error| {
        Error::DebugInfo(format!(
            "failed to read {msr:#x} on processor {processor}: {error}"
        ))
    })?;
    Ok(MsrValue {
        processor,
        msr,
        value,
    })
}

impl Render for MsrValue {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        outln!(
            "processor {}  {} ({:#x}) = {}",
            self.processor,
            msr_name(self.msr).unwrap_or("MSR"),
            self.msr,
            render_msr_value(&repl.ctx.target, self.value)
        );
    }
}

/// An MSR write, as `wrmsr` made it.
pub struct MsrWrite(MsrValue);

/// Write a model-specific register on the current processor.
///
/// Writes one model-specific register on the current processor. You can use
/// a common IA32_* name instead of the numeric MSR.
#[command(
    names = ["wrmsr"],
    category = "cpu",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Registers],
    live_only,
    capability = Msr,
    python = none
)]
fn wrmsr(session: &mut Session, msr: Msr, value: u64) -> Result<MsrWrite> {
    let processor = session.processor(None)?;
    let Msr(msr) = msr;
    session.write_msr(processor, msr, value).map_err(|error| {
        Error::DebugInfo(format!(
            "failed to write {msr:#x} on processor {processor}: {error}"
        ))
    })?;
    Ok(MsrWrite(MsrValue {
        processor,
        msr,
        value,
    }))
}

impl Render for MsrWrite {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let MsrValue {
            processor,
            msr,
            value,
        } = self.0;
        outln!(
            "processor {}  {} ({:#x}) <- {}",
            processor,
            msr_name(msr).unwrap_or("MSR"),
            msr,
            ui::addr(value)
        );
    }
}

/// Show the main KPCR data of the selected processor.
///
/// Shows the KPCR and KPRCB addresses, the thread pointers, the descriptor
/// registers, the TSS, and the available IRQL fields. On AMD64 Windows,
/// kernel GS usually points to the KPCR, and backend GS-base registers are
/// optional.
#[command(
    names = ["!pcr", "pcr"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu
)]
fn pcr(session: &mut Session, #[arg(receiver)] processor: Option<Processor>) -> Result<Pcr> {
    let processor = session.processor(processor)?;
    session.inspect_pcr(processor)
}

impl Render for Pcr {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        print_pcr(self, repl.ctx.target.arch());
    }
}

/// Show the main KPRCB data of the selected processor.
///
/// Shows the processor number, the thread pointers, the DPC and interrupt
/// counters, and the available ProcessorState metadata of the selected
/// KPRCB.
#[command(
    names = ["!prcb", "prcb"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu
)]
fn prcb(session: &mut Session, #[arg(receiver)] processor: Option<Processor>) -> Result<Prcb> {
    let processor = session.processor(processor)?;
    session.target.inspect_prcb(processor)
}

impl Render for Prcb {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_prcb(self);
    }
}

/// Show the current IRQL of a processor.
///
/// Shows the current IRQL and the Windows level name of the selected
/// processor. At a KD break-in, this is the IRQL that the debugger sees,
/// which can be different from the level before the break-in.
#[command(
    names = ["!irql", "irql"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu
)]
fn irql(session: &mut Session, #[arg(receiver)] processor: Option<Processor>) -> Result<Irql> {
    let processor = session.processor(processor)?;
    session.target.inspect_irql(processor)
}

impl Render for Irql {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_irql(self);
    }
}

/// An IDT vector, `!idt`'s argument: 0 to 255.
#[grammar(usage = "[vector]", complete = [Expression])]
fn idt_vector(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<u16>, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(None);
    };
    let value = cx.eval(&text)?.0;
    if value < u64::from(IDT_VECTOR_COUNT) {
        Ok(Some(value as u16))
    } else {
        Err(ArgError::Message(format!(
            "IDT vector {value:#x} is outside 0..255"
        )))
    }
}

/// Decode one IDT entry or the bounded 256-entry IDT.
///
/// Shows one IDT vector or all 256 entries, with the handler, selector, gate
/// type, DPL, presence, non-nt hooks, and KiIsrThunk chain hints of each
/// entry.
#[command(
    names = ["!idt", "idt"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu,
)]
fn idt(
    session: &mut Session,
    #[arg(receiver, parse = current_processor)] processor: Option<Processor>,
    #[arg(parse = idt_vector, positional)] vector: Option<u16>,
) -> Result<Idt> {
    if session.target.arch() == Arch::Arm64 {
        return Err(Error::DebugInfo(
            "!idt is not defined on ARM64 targets".into(),
        ));
    }
    let processor = session.processor(processor)?;
    session
        .inspect_idt(processor, vector)
        .map_err(|error| Error::DebugInfo(format!("IDTR unavailable: {error}")))
}

impl Render for Idt {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_idt(self);
    }
}

/// The GDT of `processor`, for `!gdt` and `dg`, which `name` the error on an
/// ARM64 target.
fn read_gdt(session: &mut Session, processor: Option<Processor>, name: &str) -> Result<Gdt> {
    if session.target.arch() == Arch::Arm64 {
        return Err(Error::DebugInfo(format!(
            "{name} is not defined on ARM64 targets"
        )));
    }
    let processor = session.processor(processor)?;
    session
        .inspect_gdt(processor)
        .map_err(|error| Error::DebugInfo(format!("GDTR unavailable: {error}")))
}

/// Decode the bounded GDT of the current processor.
///
/// Shows the bounded GDT entries of the selected processor, with the base,
/// limit, privilege, mode, and presence of each entry.
#[command(
    names = ["!gdt", "gdt"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu,
)]
fn gdt(
    session: &mut Session,
    #[arg(receiver, parse = current_processor)] processor: Option<Processor>,
) -> Result<Gdt> {
    read_gdt(session, processor, "!gdt")
}

impl Render for Gdt {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_gdt(self);
    }
}

/// A segment selector, `dg`'s argument: 16 bits.
#[derive(Clone, Copy, Debug)]
pub struct Selector(pub u16);

impl FromArg for Selector {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        match cx.eval(text)? {
            VirtAddr(value) if value <= 0xffff => Ok(Selector(value as u16)),
            _ => Err(ArgError::Message(format!(
                "'{text}' is not a 16-bit selector"
            ))),
        }
    }
}

/// The selectors `dg` decodes, with the GDT they index.
pub struct Selectors {
    gdt: Gdt,
    first: u16,
    last: u16,
}

/// Decode segment selectors from the GDT of the current processor.
///
/// Shows each selector from the first to the last, in steps of 8 as WinDbg
/// does. For each selector, it shows the descriptor base, limit, type,
/// privilege level, size (Bg/Nb), granularity (Pg/By), presence (P/NP), long
/// mode (Lo/Nl), and attribute flags. If a selector refers to an LDT (bit 2
/// set), dg reports this and does not decode the selector. 64-bit Windows has
/// no LDT.
#[command(
    names = ["dg"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn dg(
    session: &mut Session,
    #[arg(name = "first-selector")] first: Selector,
    #[arg(name = "last-selector")] last: Option<Selector>,
) -> Result<Selectors> {
    let Selector(first) = first;
    let last = last.map_or(first, |last| last.0);
    if last < first {
        return Err(Error::DebugInfo(format!(
            "the last selector {last:#x} is below the first {first:#x}"
        )));
    }
    let gdt = read_gdt(session, None, "dg")?;
    Ok(Selectors { gdt, first, last })
}

impl Render for Selectors {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_selectors(&self.gdt, (self.first..=self.last).step_by(8));
    }
}

/// Show processor identification, speed, and feature bits.
///
/// Shows the processor number, vendor, family, model, stepping, speed, and
/// feature bits if they are available. For a field that is not available,
/// ntoseye uses the triage-dump metadata.
#[command(
    names = ["!cpuinfo", "cpuinfo"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Cpu,
)]
fn cpuinfo(
    session: &mut Session,
    #[arg(receiver, parse = current_processor)] processor: Option<Processor>,
) -> Result<CpuInfo> {
    let processor = session.processor(processor)?;
    session.target.inspect_cpuinfo(processor)
}

impl Render for CpuInfo {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_cpuinfo(self);
    }
}

/// Switch to a different vCPU context.
#[command(
    names = ["vcpu"],
    category = "processes and modules",
    kind = Action,
    target = Machine,
    state = Halted,
    python = none,
)]
fn vcpu(
    state: &mut ReplState<'_>,
    #[arg(name = "id", complete = Vcpu)] requested: String,
) -> Result<()> {
    let threads = state
        .ctx
        .backend
        .thread_list()
        .map_err(|e| Error::DebugInfo(format!("failed to get vCPU list: {e}")))?;

    let thread_id = threads
        .iter()
        .find(|thread| thread.as_str() == requested)
        .cloned()
        .or_else(|| {
            Expr::eval_with_radix(&requested, &state.ctx.target, state.radix)
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
        return Err(Error::DebugInfo(format!(
            "vCPU '{requested}' not found (use 'vcpus' to list vCPUs)"
        )));
    };

    state
        .ctx
        .set_current_thread(&thread_id)
        .map_err(|e| Error::DebugInfo(format!("failed to switch vCPU: {e}")))?;

    state.clear_selected_frame();
    state.caches.refresh_symbol_context(&state.ctx.target);
    outln!("switched to vCPU {}\n", state.ctx.current_thread);

    Ok(())
}

impl ReplState<'_> {
    pub fn cmd_tilde(&mut self, line: &str) -> Result<Flow> {
        let body = line.trim().strip_prefix('~').unwrap_or_default();
        if self.ctx.target.user_dump().is_some() {
            self.cmd_tilde_user_dump(body, line);
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

    /// `~` on a user-mode minidump, over its captured threads as WinDbg's
    /// user-mode `~` does: `~` lists them; `~N`, `~~[tid]`, `~.` (the
    /// current thread), `~#` (the exception's), and `~*` name threads, which
    /// are listed, or with `s` selected, with `k` or `r` shown.
    fn cmd_tilde_user_dump(&mut self, body: &str, line: &str) {
        const USAGE: &str = "expected ~, ~N, ~~[tid], ~., ~#, or ~*, then s, k, or r";
        let Some(threads) = self.ctx.user_threads() else {
            return;
        };
        if body.is_empty() {
            print_user_threads(&threads);
            return;
        }
        let (selected, suffix): (Vec<UserThreadSummary>, &str) = if let Some(rest) =
            body.strip_prefix('*')
        {
            (threads.clone(), rest)
        } else if let Some(rest) = body.strip_prefix('.') {
            (
                threads
                    .iter()
                    .filter(|thread| thread.current)
                    .cloned()
                    .collect(),
                rest,
            )
        } else if let Some(rest) = body.strip_prefix('#') {
            let Some(thread) = threads.iter().find(|thread| thread.exception) else {
                error!("the minidump records no exception, so no thread raised one");
                return;
            };
            (vec![thread.clone()], rest)
        } else if let Some(rest) = body.strip_prefix("~[") {
            let Some((expression, rest)) = rest.split_once(']') else {
                error!("'{line}' has no closing ']'; {USAGE}");
                return;
            };
            let Some(tid) = self.eval_or_report(expression) else {
                return;
            };
            let Some(thread) = threads.iter().find(|thread| u64::from(thread.tid) == tid.0) else {
                error!("the minidump has no thread with id {:#x}", tid.0);
                return;
            };
            (vec![thread.clone()], rest)
        } else {
            let digits = body.chars().take_while(|ch| ch.is_ascii_digit()).count();
            let Some(index) = body[..digits].parse::<usize>().ok() else {
                error!("invalid thread selector '{line}'; {USAGE}");
                return;
            };
            let Some(thread) = threads.get(index) else {
                error!(
                    "thread {index} out of range (the minidump holds {} threads)",
                    threads.len()
                );
                return;
            };
            (vec![thread.clone()], &body[digits..])
        };
        match suffix.trim() {
            "" => print_user_threads(&selected),
            "s" => {
                let [thread] = selected.as_slice() else {
                    error!("'{line}' names {} threads; s selects one", selected.len());
                    return;
                };
                match self.ctx.set_current_thread(&thread.id) {
                    Ok(()) => {
                        self.caches.refresh_symbol_context(&self.ctx.target);
                        outln!(
                            "switched to thread {} ({})\n",
                            thread.index,
                            ui::thread_id(&thread.id)
                        );
                    }
                    Err(error) => error!("failed to switch thread: {error}"),
                }
            }
            action @ ("k" | "r") => {
                let original = self.ctx.current_thread.clone();
                for thread in &selected {
                    if selected.len() > 1 {
                        outln!(
                            "{}",
                            ui::muted(&format!("thread {} ({})", thread.index, thread.id))
                        );
                    }
                    if let Err(error) = self.ctx.set_current_thread(&thread.id) {
                        error!("failed to switch to thread {}: {error}", thread.id);
                        continue;
                    }
                    self.caches.refresh_symbol_context(&self.ctx.target);
                    if let Err(error) = self.dispatch_line(action) {
                        error!("thread {} command failed: {error}", thread.id);
                    }
                }
                if let Err(error) = self.ctx.set_current_thread(&original) {
                    error!("failed to restore thread {original}: {error}");
                } else {
                    self.caches.refresh_symbol_context(&self.ctx.target);
                }
            }
            other => error!("unsupported thread command '{other}'; {USAGE}"),
        }
    }
}

/// List vCPU contexts and their RIP values.
///
/// `~Ns` selects processor N (zero-based), and `t` and `p` then step that
/// processor. The vCPU id that the list shows also works in place of N
/// (`~p01.03s`, `~p01.03k`). Over `kd` and `kdnet` on an AMD64 target, the
/// other processors run during the step, as in WinDbg. On an ARM64 target,
/// only the processor that stopped the target can step over `kd` or `kdnet`.
/// If a vCPU halted in the Windows hypervisor (VBS), the list also shows
/// where its VTL0 execution stopped, from the saved state of the hypervisor.
/// `~Ns` on that vCPU selects the VTL0 context, and `.cxr` selects the
/// hypervisor registers. A vCPU stopped on the hypervisor's VM-exit entry
/// from outside shows its saved state as `(may be one exit behind)` and keeps
/// the hypervisor registers: KVM writes that state when it enters the
/// hypervisor, so it can still describe the previous exit. A breakpoint on
/// the entry fires after that write, so a vCPU stopped on one shows the
/// current exit.
#[command(
    names = ["~", "vcpus"],
    category = "processes and modules",
    kind = Query,
    state = Halted,
    python = none,
)]
fn vcpus(session: &mut Session) -> Result<Contexts> {
    // A user dump's contexts are its captured threads.
    if let Some(threads) = session.user_threads() {
        return Ok(Contexts::UserThreads(threads));
    }
    let pb = output::native_progress_bar(0, "reading the vCPUs").unwrap_or_else(|| {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.black.bright} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("{}", "Waiting on GDB...".bright_black()));
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    });
    let vcpus = session.vcpus();
    pb.finish_and_clear();
    vcpus.map(Contexts::Vcpus)
}

/// The register contexts `~` lists.
enum Contexts {
    Vcpus(Vec<VcpuInfo>),
    /// A user-mode minidump's captured threads.
    UserThreads(Vec<UserThreadSummary>),
}

impl Render for Contexts {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        match self {
            Self::UserThreads(threads) => print_user_threads(threads),
            Self::Vcpus(vcpus) => {
                repl.caches.refresh_vcpus(repl.ctx.backend.as_mut());
                #[cfg(feature = "cli")]
                native::render(|| native::lists::vcpus(vcpus), || print_vcpus(vcpus));
                #[cfg(not(feature = "cli"))]
                print_vcpus(vcpus);
            }
        }
    }
}

/// A user-mode minidump's thread list, as WinDbg's `~` shows it: `.` marks
/// the current thread and `#` the exception's.
fn print_user_threads(threads: &[UserThreadSummary]) {
    let mut builder = Builder::default();
    builder.push_record(["", "#", "Id", "Suspend", "Teb", "Symbol", "Name"]);
    for thread in threads {
        let marker = match (thread.current, thread.exception) {
            (true, _) => ".",
            (false, true) => "#",
            (false, false) => "",
        };
        let symbol = match (thread.rip, &thread.symbol, &thread.error) {
            (Some(_), Some(symbol), _) => symbol.clone(),
            (Some(rip), None, _) => format!("{rip:#x}"),
            (None, _, Some(error)) => ui::muted(&format!("no context: {error}")).to_string(),
            (None, _, None) => ui::muted("no context").to_string(),
        };
        builder.push_record([
            marker.to_string(),
            thread.index.to_string(),
            thread.id.clone(),
            thread.suspend_count.to_string(),
            ui::addr(thread.teb).to_string(),
            symbol,
            thread.name.clone().unwrap_or_default(),
        ]);
    }
    print_padded_table(builder);
}

/// The vCPU list: what each vCPU runs, with the lines below a vCPU in the
/// hypervisor.
fn print_vcpus(vcpus: &[VcpuInfo]) {
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
                vcpu.symbol.clone().unwrap_or_else(|| format!("{rip:#x}")),
            ),
            None => (
                ui::muted("unavailable"),
                vcpu.error.clone().unwrap_or_default(),
            ),
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
