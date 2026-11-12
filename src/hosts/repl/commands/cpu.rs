use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use ntoseye_macros::{command, grammar};
use owo_colors::OwoColorize;
use tabled::builder::Builder;

use crate::arch::{Arch, Family};
use crate::backend::dbg_backend::{processor_index_from_backend_thread_id, thread_label};
use crate::base::error::{Error, Result};
use crate::base::output;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, FromArg};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::cpu::{
    CpuInfo, CpuTriageFallback, DescriptorRegister, Gdt, GdtDescriptor, Idt, IdtGate, Irql, Pcr,
    Prcb, Processor, SpecialRegistersArea, msr_kind, msr_name, parse_msr_name,
};
use crate::nt::target::{DiagnosticValue, SelectedFrame, ServedVp, Target};
use crate::session::Session;
use crate::session::{UserThreadSummary, VcpuInfo};

use super::diagnostics::{UnavailableNotes, yes_no};

const IDT_VECTOR_COUNT: u16 = 256;
const MSR_SWITCH: &str = "/p";

/// What a `~` command names: one processor by number, one vCPU by the id
/// `~` lists, or every processor (`~*`).
enum TildeSelector {
    Number(u64),
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
        if let Some(msr) = parse_msr_name(cx.state.ctx.target.arch(), text) {
            return Ok(Msr(msr));
        }
        let value = cx.eval(text)?.0;
        u32::try_from(value)
            .map(Msr)
            .map_err(|_| ArgError::Message(format!("MSR {value:#x} does not fit in 32 bits")))
    }
}

/// The fields of a block that could not be read, as the shared
/// [`UnavailableNotes`] collects them, with any rendering for the ones that
/// could.
#[derive(Default)]
struct Gaps(UnavailableNotes);

impl Gaps {
    /// `value` rendered, or `-` with `field` noted when it is unavailable.
    fn cell<T>(
        &mut self,
        field: impl Into<String>,
        value: &DiagnosticValue<T>,
        render: impl FnOnce(&T) -> String,
    ) -> String {
        match value {
            DiagnosticValue::Available(value) => render(value),
            DiagnosticValue::Unavailable(error) => self.0.missing(&field.into(), error),
        }
    }

    /// Note `field` as unavailable for `error`.
    fn note(&mut self, field: impl Into<String>, error: &str) {
        self.0.missing(&field.into(), error);
    }

    /// The block's note, `indent` in.
    fn print(&self, indent: &str) {
        self.0.print(indent);
    }
}

fn address_text(value: &VirtAddr) -> String {
    ui::addr(value.0)
}

/// A pointer field, `-` when it is null (no next thread, no KD version
/// block).
fn pointer_text(value: &VirtAddr) -> String {
    ui::addr_opt(*value)
}

fn decimal_text(value: &u64) -> String {
    format!("{value} ({value:#x})")
}

fn hex_text<T: Copy + Into<u64>>(value: &T) -> String {
    let value: u64 = (*value).into();
    format!("{value:#x}")
}

fn yes_no_text(value: &bool) -> String {
    yes_no(*value).to_string()
}

fn descriptor_text(value: &DescriptorRegister) -> String {
    format!("base {} limit {:#x}", ui::addr(value.base.0), value.limit)
}

/// An ARM64 `_KPCR` embeds its PRCB, which the first line names, and has
/// no descriptor tables or TSS, so those rows are AMD64's alone.
fn print_pcr(detail: &Pcr, arch: Arch) {
    let mut gaps = Gaps::default();
    let kpcr = gaps.cell("KPCR address", &detail.kpcr, address_text);
    outln!(
        "KPCR for processor {} at {} (KPRCB {})",
        detail.processor,
        kpcr,
        ui::addr(detail.kprcb.0)
    );
    let mut fields = vec![(
        "KdVersionBlock",
        gaps.cell("KdVersionBlock", &detail.kd_version_block, pointer_text),
    )];
    // An x86-family KPCR points at its KPRCB; an ARM64 one holds it.
    if arch.family() == Family::X86 {
        fields.push((
            "CurrentPrcb",
            gaps.cell("CurrentPrcb", &detail.current_prcb, address_text),
        ));
    }
    fields.push(("Irql", gaps.cell("Irql", &detail.irql, decimal_text)));
    fields.push(("Self", gaps.cell("Self", &detail.self_pcr, address_text)));
    print_struct_fields("  ", 20, &fields);
    // The KPRCB's fields, a sub-block whose colons stay in the KPCR's column.
    outln!("  KPRCB fields");
    let mut fields = vec![
        (
            "CurrentThread",
            gaps.cell("CurrentThread", &detail.current_thread, address_text),
        ),
        (
            "NextThread",
            gaps.cell("NextThread", &detail.next_thread, pointer_text),
        ),
        (
            "IdleThread",
            gaps.cell("IdleThread", &detail.idle_thread, address_text),
        ),
    ];
    // Descriptor tables and the TSS are the x86 family's.
    if arch.family() == Family::X86 {
        fields.push(("IDTR", gaps.cell("IDTR", &detail.idtr, descriptor_text)));
        fields.push(("GDTR", gaps.cell("GDTR", &detail.gdtr, descriptor_text)));
        fields.push((
            "TssBase",
            gaps.cell("TssBase", &detail.tss_base, address_text),
        ));
    }
    print_struct_fields("    ", 18, &fields);
    gaps.print("  ");
}

/// Windows structure fields, `Name : value`, `indent` in with the names
/// padded to `width`.
fn print_struct_fields(indent: &str, width: usize, fields: &[(&str, String)]) {
    for (name, value) in fields {
        outln!("{indent}{name:<width$}: {value}");
    }
}

/// An area embedded in the KPRCB: its address, size and type.
fn special_registers_text(value: &SpecialRegistersArea) -> String {
    format!(
        "{} ({:#x} bytes, {})",
        ui::addr(value.address.0),
        value.size,
        value.name
    )
}

fn print_prcb(detail: &Prcb) {
    outln!(
        "KPRCB for processor {} at {}",
        detail.processor,
        ui::addr(detail.kprcb.0)
    );
    let mut gaps = Gaps::default();
    let mut fields = vec![
        ("Number", gaps.cell("Number", &detail.number, decimal_text)),
        (
            "CurrentThread",
            gaps.cell("CurrentThread", &detail.current_thread, address_text),
        ),
        (
            "NextThread",
            gaps.cell("NextThread", &detail.next_thread, pointer_text),
        ),
        (
            "IdleThread",
            gaps.cell("IdleThread", &detail.idle_thread, address_text),
        ),
        (
            "DpcRoutineActive",
            gaps.cell("DpcRoutineActive", &detail.dpc_routine_active, decimal_text),
        ),
        (
            "InterruptCount",
            gaps.cell("InterruptCount", &detail.interrupt_count, decimal_text),
        ),
    ];
    match &detail.processor_state {
        DiagnosticValue::Available(state) => {
            fields.push((
                "ProcessorState",
                format!(
                    "{} ({:#x} bytes, {})",
                    ui::addr(state.address.0),
                    state.size,
                    state.name
                ),
            ));
            fields.push((
                "ContextFrame",
                gaps.cell("ContextFrame", &state.context_frame, address_text),
            ));
            fields.push((
                "SpecialRegisters",
                gaps.cell(
                    "SpecialRegisters",
                    &state.special_registers,
                    special_registers_text,
                ),
            ));
        }
        DiagnosticValue::Unavailable(error) => {
            gaps.note("ProcessorState", error);
            fields.push(("ProcessorState", "-".to_string()));
        }
    }
    print_struct_fields("  ", 20, &fields);
    gaps.print("  ");
}

fn print_irql(detail: &Irql) {
    match (&detail.value, &detail.level_name) {
        (DiagnosticValue::Available(value), DiagnosticValue::Available(name)) => {
            outln!("processor {} IRQL {name} ({value:#x})", detail.processor);
        }
        (DiagnosticValue::Unavailable(error), _) => {
            error!("current IRQL unavailable: {error}");
        }
        (_, DiagnosticValue::Unavailable(error)) => {
            error!("current IRQL unavailable: {error}");
        }
    }
}

/// One IDT gate's row of the `!idt` table, and a row under it for the
/// interrupt object connected to a KiIsrThunk vector.
fn push_idt_entry(builder: &mut Builder, gaps: &mut Gaps, detail: &IdtGate) {
    let vector = format!("{:02x}", detail.vector);
    let field = |name: &str| format!("vector {vector} {name}");
    let handler = match &detail.handler {
        DiagnosticValue::Available(handler) => *handler,
        DiagnosticValue::Unavailable(error) => {
            gaps.note(field("gate"), error);
            let mut row = vec![vector];
            row.resize(7, "-".to_string());
            builder.push_record(row);
            return;
        }
    };
    // A handler with no symbol is its address, as a frame's call site is.
    let symbol = gaps.cell(field("symbol"), &detail.symbol, |symbol| {
        symbol
            .clone()
            .unwrap_or_else(|| format!("{:#x}", handler.0))
    });
    let selector = gaps.cell(field("selector"), &detail.selector, |selector| {
        format!("{selector:#06x}")
    });
    let hook = matches!(&detail.non_nt_hook, DiagnosticValue::Available(true));
    builder.push_record([
        vector.clone(),
        selector,
        gaps.cell(field("IST"), &detail.ist, u8::to_string),
        gaps.cell(field("type"), &detail.gate_name, String::clone),
        gaps.cell(field("DPL"), &detail.dpl, u8::to_string),
        gaps.cell(field("present bit"), &detail.present, yes_no_text),
        format!("{symbol}{}", if hook { "  [NON-NT HOOK]" } else { "" }),
    ]);
    if let DiagnosticValue::Available(Some(chain)) = &detail.ki_isr_thunk {
        let mut row = vec![String::new(); 6];
        row.push(format!("connected: {chain}"));
        builder.push_record(row);
    }
}

fn print_idt(detail: &Idt) {
    outln!(
        "IDT for processor {} at {}, limit {:#x}",
        detail.processor,
        ui::addr(detail.base.0),
        detail.limit
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Vector", "Selector", "IST", "Type", "DPL", "Present", "Handler",
    ]);
    let mut gaps = Gaps::default();
    // Gates past the IDTR limit are memory the processor never reads.
    let covered = detail.limit.saturating_add(1) / 16;
    for entry in detail
        .entries
        .iter()
        .filter(|entry| u64::from(entry.vector) < covered)
    {
        push_idt_entry(&mut builder, &mut gaps, entry);
    }
    print_padded_table(builder);
    gaps.print("");
    if detail.truncated {
        outln!(
            "{}",
            ui::muted(&format!(
                "the IDT limit covers only {covered} vectors; vectors past it are not shown"
            ))
        );
    }
}

/// One descriptor's row of the `!gdt` table.
fn push_gdt_entry(builder: &mut Builder, gaps: &mut Gaps, detail: &GdtDescriptor) {
    let field = |name: &str| format!("entry {} {name}", detail.index);
    if let DiagnosticValue::Unavailable(error) = &detail.raw {
        gaps.note(field("descriptor"), error);
        let mut row = vec![detail.index.to_string()];
        row.resize(8, "-".to_string());
        builder.push_record(row);
        return;
    }
    let mode = match &detail.long_mode {
        DiagnosticValue::Available(true) => Some("L"),
        DiagnosticValue::Available(false) => match &detail.default_size {
            DiagnosticValue::Available(true) => Some("D/B"),
            _ => None,
        },
        DiagnosticValue::Unavailable(_) => None,
    };
    let granularity = match &detail.granularity {
        DiagnosticValue::Available(true) => Some("G"),
        _ => None,
    };
    let flags: Vec<&str> = mode.into_iter().chain(granularity).collect();
    builder.push_record([
        detail.index.to_string(),
        gaps.cell(field("base"), &detail.base, address_text),
        gaps.cell(field("limit"), &detail.limit, hex_text),
        gaps.cell(field("type"), &detail.type_code, hex_text),
        gaps.cell(field("kind"), &detail.descriptor_kind, String::clone),
        gaps.cell(field("DPL"), &detail.dpl, u8::to_string),
        gaps.cell(field("present bit"), &detail.present, yes_no_text),
        if flags.is_empty() {
            "-".to_string()
        } else {
            flags.join(" ")
        },
    ]);
}

fn print_gdt(detail: &Gdt) {
    outln!(
        "GDT for processor {} at {}, limit {:#x} ({} entries)",
        detail.processor,
        ui::addr(detail.base.0),
        detail.limit,
        detail.entry_count
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Index", "Base", "Limit", "Type", "Kind", "DPL", "Present", "Flags",
    ]);
    let mut gaps = Gaps::default();
    for entry in &detail.entries {
        push_gdt_entry(&mut builder, &mut gaps, entry);
    }
    print_padded_table(builder);
    gaps.print("");
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
                    DiagnosticValue::Unavailable(error) => {
                        format!("descriptor unreadable: {error}")
                    }
                    DiagnosticValue::Available(_) => "descriptor undecodable".to_string(),
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
}

/// Labeled fields under a heading, two spaces in, their values in one column.
fn print_fields(fields: &[(String, String)]) {
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, value) in fields {
        outln!("  {label:<width$}  {value}");
    }
}

pub fn print_cpuinfo(detail: &CpuInfo) {
    let mut gaps = Gaps::default();
    if detail.source == "triage-dump PRCB metadata" {
        outln!("CPU information from triage-dump PRCB metadata");
        print_fields(&[
            ("processor number".into(), detail.processor.to_string()),
            (
                "vendor".into(),
                gaps.cell("vendor", &detail.vendor, String::clone),
            ),
            (
                "family".into(),
                gaps.cell("family", &detail.family, hex_text),
            ),
            ("model".into(), "-".into()),
            ("stepping".into(), "-".into()),
            (
                "speed MHz".into(),
                gaps.cell("speed", &detail.mhz, u64::to_string),
            ),
            ("feature bits".into(), "-".into()),
        ]);
        gaps.print("  ");
        return;
    }
    let kprcb = gaps.cell("KPRCB address", &detail.kprcb, address_text);
    outln!(
        "CPU information for processor {} (KPRCB {})",
        detail.processor,
        kprcb
    );
    // Family, model and stepping in hex, as `vertarget` and the CPUID
    // signature give them.
    let mut fields = vec![
        (
            "vendor".to_string(),
            gaps.cell("vendor", &detail.vendor, String::clone),
        ),
        (
            "vendor id".to_string(),
            gaps.cell("vendor id", &detail.vendor_id, hex_text),
        ),
        (
            "family".to_string(),
            gaps.cell("family", &detail.family, hex_text),
        ),
        (
            "model".to_string(),
            gaps.cell("model", &detail.model, hex_text),
        ),
        (
            "stepping".to_string(),
            gaps.cell("stepping", &detail.stepping, hex_text),
        ),
        (
            "speed MHz".to_string(),
            gaps.cell("speed", &detail.mhz, u64::to_string),
        ),
    ];
    // Each KPRCB feature field (`FeatureBits`) under a label in the
    // block's words (`feature bits`), its value a flag set in hex.
    let features: Vec<(String, String)> = detail
        .feature_bits
        .iter()
        .filter_map(|feature| match &feature.value {
            DiagnosticValue::Available(value) => {
                Some((field_words(&feature.name), format!("{value:#x}")))
            }
            DiagnosticValue::Unavailable(_) => None,
        })
        .collect();
    if features.is_empty() {
        fields.push(("feature bits".to_string(), "-".to_string()));
    }
    fields.extend(features);
    print_fields(&fields);
    gaps.print("  ");
    if let Some(fallback) = detail.triage_fallback.as_ref() {
        outln!();
        print_triage_fallback(fallback);
    }
}

/// A structure field's name as lowercase words: `FeatureBits` as
/// `feature bits`.
fn field_words(name: &str) -> String {
    let mut words = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            words.push(' ');
        }
        words.push(ch.to_ascii_lowercase());
    }
    words
}

fn print_triage_fallback(detail: &CpuTriageFallback) {
    outln!("CPU information from triage-dump PRCB metadata");
    print_fields(&[
        (
            "processor number".into(),
            detail.processor_number.to_string(),
        ),
        ("vendor".into(), detail.vendor.to_string()),
        ("family".into(), format!("{:#x}", detail.family)),
        ("model".into(), "-".into()),
        ("stepping".into(), "-".into()),
        ("speed MHz".into(), detail.mhz.to_string()),
        ("feature bits".into(), "-".into()),
    ]);
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
/// show that MSR access is unavailable. On an ARM64 target the register is
/// a system register: by name (MIDR_EL1, TTBR1_EL1, CNTVCT_EL0, ...), as
/// S<op0>_<op1>_C<n>_C<m>_<op2>, or by the number KD reads it by,
/// op0<<16 | op1<<12 | CRn<<8 | CRm<<4 | op2 (MIDR_EL1 is 0x30000).
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
        let arch = repl.ctx.target.arch();
        outln!(
            "processor {}  {} ({:#x}) = {}",
            self.processor,
            msr_name(arch, self.msr).unwrap_or(msr_kind(arch)),
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
/// a common IA32_* name instead of the numeric MSR. On an ARM64 target the
/// register is a system register, named as rdmsr takes it.
#[command(
    names = ["wrmsr"],
    category = "cpu",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Registers],
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
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let arch = repl.ctx.target.arch();
        let MsrValue {
            processor,
            msr,
            value,
        } = self.0;
        outln!(
            "processor {}  {} ({:#x}) <- {}",
            processor,
            msr_name(arch, msr).unwrap_or(msr_kind(arch)),
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
/// type, DPL, presence, and non-nt hooks of each entry. Under a vector that
/// dispatches through KiIsrThunk, the KINTERRUPT the processor has
/// connected to it and its service routine.
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
    let arch = session.target.arch();
    // Only an x86-family processor dispatches interrupts through an IDT.
    if arch.family() != Family::X86 {
        return Err(Error::DebugInfo(format!(
            "!idt is not defined on {} targets",
            arch.label()
        )));
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
    let arch = session.target.arch();
    // Only an x86-family processor has a GDT.
    if arch.family() != Family::X86 {
        return Err(Error::DebugInfo(format!(
            "{name} is not defined on {} targets",
            arch.label()
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

/// Switch to another processor, by its number.
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
    #[arg(name = "processor", complete = Vcpu)] requested: String,
) -> Result<()> {
    let threads = state
        .ctx
        .backend
        .thread_list()
        .map_err(|e| Error::DebugInfo(format!("failed to list the processors: {e}")))?;

    // Processor numbers are decimal, as `~` and the prompt show them.
    let thread_id = requested.parse::<u16>().ok().and_then(|number| {
        threads
            .iter()
            .find(|thread| processor_index_from_backend_thread_id(thread) == Some(number))
            .cloned()
    });
    let Some(thread_id) = thread_id else {
        return Err(Error::DebugInfo(format!(
            "no processor '{requested}' (`~` lists the processors)"
        )));
    };

    state
        .ctx
        .set_current_thread(&thread_id)
        .map_err(|e| Error::DebugInfo(format!("failed to switch processor: {e}")))?;

    state.clear_selected_frame();
    state.caches.refresh_symbol_context(&state.ctx.target);
    outln!("switched to {}", ui::thread(&state.ctx.current_thread));

    Ok(())
}

impl ReplState<'_> {
    pub fn cmd_tilde(&mut self, line: &str) -> Result<Flow> {
        let body = line.trim().strip_prefix('~').unwrap_or_default();
        if self.ctx.target.user_dump().is_some() {
            self.cmd_tilde_user_dump(body, line);
            return Ok(Flow::Continue);
        }
        // A processor is named by its number, as `~` lists it.
        let (selector, suffix) = if let Some(rest) = body.strip_prefix('*') {
            (TildeSelector::All, rest)
        } else {
            let digits = body.chars().take_while(|ch| ch.is_ascii_digit()).count();
            if digits == 0 {
                error!(
                    "invalid processor selector '{}'; expected ~, ~N[s|k|r], or ~*k",
                    line
                );
                return Ok(Flow::Continue);
            }
            // Decimal, as WinDbg reads `~N` and as `~` lists the processors.
            let selector = match body[..digits].parse::<u64>() {
                Ok(value) => TildeSelector::Number(value),
                Err(_) => {
                    error!("processor {} out of range", &body[..digits]);
                    return Ok(Flow::Continue);
                }
            };
            (selector, &body[digits..])
        };
        let suffix = suffix.trim();
        let command = match suffix {
            "" | "s" => None,
            _ => match tilde_command(suffix) {
                Some(command) => Some(command),
                None => {
                    error!(
                        "unsupported processor command '{suffix}'; expected ~N or ~*, then s, a k command, or r"
                    );
                    return Ok(Flow::Continue);
                }
            },
        };
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
            TildeSelector::All => ids.clone(),
        };
        if selected.is_empty() {
            error!("processor not found");
            return Ok(Flow::Continue);
        }
        let original = self.ctx.current_thread.clone();
        let Some(command) = command else {
            let id = selected[0].clone();
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch processor: {}", error);
            } else {
                self.caches.refresh_symbol_context(&self.ctx.target);
                outln!("switched to {}", ui::thread(&id));
            }
            return Ok(Flow::Continue);
        };

        // Several processors' records are told apart by a line naming each,
        // as `~*k` on a user dump names each thread.
        let several = selected.len() > 1;
        let selection = self.ctx.target.selected_frame.clone();
        for (index, id) in selected.into_iter().enumerate() {
            if several {
                if index > 0 {
                    outln!();
                }
                outln!("{}", ui::muted(&ui::thread(&id)));
            }
            if let Err(error) = self.ctx.set_current_thread(&id) {
                error!("failed to switch to {}: {}", ui::thread(&id), error);
                continue;
            }
            self.caches.refresh_symbol_context(&self.ctx.target);
            if let Err(error) = self.dispatch_line(command) {
                error!("{} command failed: {}", ui::thread(&id), error);
            }
        }
        self.restore_thread_and_selection(&original, selection);
        Ok(Flow::Continue)
    }

    /// Return to `original` and the frame or context (`.frame`, `.ecxr`)
    /// selected on it before `~` ran a command on other threads, since
    /// switching threads drops a selection.
    fn restore_thread_and_selection(&mut self, original: &str, selection: Option<SelectedFrame>) {
        if let Err(error) = self.ctx.set_current_thread(original) {
            error!("failed to restore {}: {error}", ui::thread(original));
            return;
        }
        if let Some(selection) = selection {
            self.ctx.select_frame(selection);
        }
        self.caches.refresh_symbol_context(&self.ctx.target);
    }

    /// `~` on a user-mode minidump, over its captured threads as WinDbg's
    /// user-mode `~` does: `~` lists them; `~N`, `~~[tid]`, `~.` (the
    /// current thread), `~#` (the exception's), and `~*` name threads, which
    /// are listed, or with `s` selected, with `k` or `r` shown.
    fn cmd_tilde_user_dump(&mut self, body: &str, line: &str) {
        const USAGE: &str = "expected ~, ~N, ~~[tid], ~., ~#, or ~*, then s, a k command, or r";
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
                            "switched to thread {} ({})",
                            thread.index,
                            ui::thread_id(&thread.id)
                        );
                    }
                    Err(error) => error!("failed to switch thread: {error}"),
                }
            }
            suffix => {
                let Some(command) = tilde_command(suffix) else {
                    error!("unsupported thread command '{suffix}'; {USAGE}");
                    return;
                };
                let original = self.ctx.current_thread.clone();
                let selection = self.ctx.target.selected_frame.clone();
                for (index, thread) in selected.iter().enumerate() {
                    if selected.len() > 1 {
                        if index > 0 {
                            outln!();
                        }
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
                    if let Err(error) = self.dispatch_line(command) {
                        error!("thread {} command failed: {error}", thread.id);
                    }
                }
                self.restore_thread_and_selection(&original, selection);
            }
        }
    }
}

/// The command `~` runs on each thread it names: one of the `k` family or
/// `r`, with its arguments (`~*kv`, `~0k 3`, `~*r rip`), as WinDbg runs the
/// command after a thread selector. `None` for any other command, which `~`
/// does not run.
fn tilde_command(suffix: &str) -> Option<&str> {
    let name = suffix.split_whitespace().next()?;
    ["k", "kb", "kf", "kn", "kp", "kv", "r"]
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
        .then_some(suffix)
}

/// List the processors and where each is.
///
/// `~Ns` selects processor N, numbered from 0 as Windows numbers them, and
/// `t` and `p` then step that processor. Over `kd` and `kdnet` on an AMD64 target, the
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
                let current = repl.ctx.current_thread.as_str();
                let pc = repl.ctx.target.arch().pc_register().to_uppercase();
                print_vcpus(vcpus, current, &pc);
            }
        }
    }
}

/// A user-mode minidump's thread list, as WinDbg's `~` shows it: `.` marks
/// the current thread and `#` the exception's.
fn print_user_threads(threads: &[UserThreadSummary]) {
    let mut builder = Builder::default();
    builder.push_record(["", "#", "Id", "Suspend", "TEB", "Symbol", "Name"]);
    // Threads the dump holds no context for, said once under the table.
    let mut notes = Vec::new();
    for thread in threads {
        let marker = match (thread.current, thread.exception) {
            (true, _) => ".",
            (false, true) => "#",
            (false, false) => "",
        };
        let symbol = match (thread.rip, &thread.symbol, &thread.error) {
            (Some(_), Some(symbol), _) => symbol.clone(),
            (Some(rip), None, _) => format!("{rip:#x}"),
            (None, _, error) => {
                notes.push(match error {
                    Some(error) => format!("thread {} has no context: {error}", thread.index),
                    None => format!("thread {} has no context", thread.index),
                });
                "-".to_string()
            }
        };
        builder.push_record([
            marker.to_string(),
            thread.index.to_string(),
            thread.id.clone(),
            thread.suspend_count.to_string(),
            ui::addr(thread.teb).to_string(),
            symbol,
            thread.name.clone().unwrap_or_else(|| "-".to_string()),
        ]);
    }
    print_padded_table(builder);
    for note in notes {
        outln!("{}", ui::muted(&note));
    }
}

/// The vCPU list: what each vCPU runs, with the lines below a vCPU in the
/// hypervisor. `.` marks `current`, the selected vCPU, as WinDbg's `~` marks
/// the current thread. `pc` heads the program counter's column: `RIP`, or
/// `PC` on ARM64.
fn print_vcpus(vcpus: &[VcpuInfo], current: &str, pc: &str) {
    // The marker column, and the two spaces after it.
    let marker_column = 3;
    // Where the Symbol column starts: each column is as wide as its
    // widest cell, plus two spaces. The lines below a vCPU wrap from
    // there, after their three-column tree glyph.
    let widest = |header: &str, cells: &mut dyn Iterator<Item = usize>| {
        cells.fold(header.len(), usize::max) + 2
    };
    let symbol_column = marker_column
        + widest(
            "Processor",
            &mut vcpus
                .iter()
                .map(|vcpu| thread_label(&vcpu.id).chars().count()),
        )
        + widest(
            pc,
            &mut vcpus.iter().map(|vcpu| match vcpu.rip {
                Some(0) => 1,
                Some(_) => 16,
                None => 1,
            }),
        )
        + widest(
            "Context",
            &mut vcpus.iter().map(|vcpu| vcpu.context.chars().count()),
        );

    let mut builder = Builder::default();
    builder.push_record(["", "Processor", pc, "Context", "Symbol"]);
    // Processors whose registers could not be read, said under the table.
    let mut notes = Vec::new();
    for vcpu in vcpus {
        let (rip_cell, symbol_cell) = match vcpu.rip {
            // A dump that captured no context for a processor records a
            // zero RIP, which names no place.
            Some(0) => ("-".to_string(), "-".to_string()),
            Some(rip) => (
                ui::addr(rip),
                vcpu.symbol.clone().unwrap_or_else(|| format!("{rip:#x}")),
            ),
            None => {
                notes.push(match &vcpu.error {
                    Some(error) => format!("{}: {error}", ui::thread(&vcpu.id)),
                    None => format!("{}: registers unavailable", ui::thread(&vcpu.id)),
                });
                ("-".to_string(), "-".to_string())
            }
        };
        let context = if vcpu.context.is_empty() {
            "-".to_string()
        } else {
            vcpu.context.to_string()
        };
        let marker = if vcpu.id == current { "." } else { "" };
        builder.push_record(vec![
            marker.to_string(),
            thread_label(&vcpu.id),
            rip_cell,
            context,
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
            builder.push_record(vec![
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                line,
            ]);
        }
    }

    print_padded_table(builder);
    for note in notes {
        outln!("{}", ui::muted(&note));
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

#[cfg(test)]
mod tests {
    use super::tilde_command;

    #[test]
    fn tilde_command_accepts_the_k_family_and_r_with_arguments() {
        for suffix in ["k", "kv", "kb", "KP", "k 3", "kf 2", "r", "r rip"] {
            assert_eq!(tilde_command(suffix), Some(suffix), "{suffix}");
        }
        for suffix in ["kd", "x", "ks", "rr", "u @pc"] {
            assert_eq!(tilde_command(suffix), None, "{suffix}");
        }
    }
}
