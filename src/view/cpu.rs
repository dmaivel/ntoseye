//! cpu: [`View`] builders for the structured inspectors.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use crate::target::cpu::{
    CpuFeatureBits as FeatureBitsDetail, CpuInfoDetail, CpuTriageInfo, DescriptorDetail, GdtDetail,
    GdtEntryDetail, IdtDetail, IdtEntryDetail, IrqlDetail, PcrDetail, PrcbDetail,
    ProcessorStateDetail, SpecialRegistersDetail,
};
use crate::types::VirtAddr;

/// A descriptor-table register (IDTR/GDTR).
#[record]
pub struct DescriptorRegister {
    pub base: VirtAddr,
    /// The table limit: the table size in bytes, minus one.
    pub limit: u64,
}

/// The location of `_KSPECIAL_REGISTERS` in a processor state.
#[record]
pub struct SpecialRegistersArea {
    pub address: VirtAddr,
    /// The size of the structure in bytes.
    pub size: u64,
    /// The type name.
    pub name: String,
}

/// The `_KPROCESSOR_STATE` embedded in a `_KPRCB`.
#[record]
pub struct ProcessorStateArea {
    pub address: VirtAddr,
    /// The size of the structure in bytes.
    pub size: u64,
    /// The type name.
    pub name: String,
    /// The address of the `_CONTEXT` embedded in the processor state.
    pub context_frame: DiagnosticValue<VirtAddr>,
    pub special_registers: DiagnosticValue<SpecialRegistersArea>,
}

/// The main KPCR and KPRCB data of a processor (`!pcr`). A field is a
/// diagnostic if its read can fail separately from the other reads.
#[record]
pub struct Pcr {
    /// The processor number.
    pub processor: u16,
    /// The `_KPCR` address.
    pub kpcr: DiagnosticValue<VirtAddr>,
    /// The `_KPRCB` address.
    pub kprcb: VirtAddr,
    /// `_KPCR.KdVersionBlock`.
    pub kd_version_block: DiagnosticValue<VirtAddr>,
    /// `_KPCR.CurrentPrcb`.
    pub current_prcb: DiagnosticValue<VirtAddr>,
    /// The current IRQL.
    pub irql: DiagnosticValue<u64>,
    /// `_KPCR.Self`.
    pub self_pcr: DiagnosticValue<VirtAddr>,
    /// The running `_KTHREAD`.
    pub current_thread: DiagnosticValue<VirtAddr>,
    /// The `_KTHREAD` selected to run next.
    pub next_thread: DiagnosticValue<VirtAddr>,
    /// The idle `_KTHREAD` of the processor.
    pub idle_thread: DiagnosticValue<VirtAddr>,
    /// The interrupt descriptor table register.
    pub idtr: DiagnosticValue<DescriptorRegister>,
    /// The global descriptor table register.
    pub gdtr: DiagnosticValue<DescriptorRegister>,
    /// The address of the task state segment.
    pub tss_base: DiagnosticValue<VirtAddr>,
}

/// Selected `_KPRCB` fields of a processor (`!prcb`).
#[record]
pub struct Prcb {
    /// The processor number.
    pub processor: u16,
    /// The `_KPRCB` address.
    pub kprcb: VirtAddr,
    /// `_KPRCB.Number`.
    pub number: DiagnosticValue<u64>,
    /// The running `_KTHREAD`.
    pub current_thread: DiagnosticValue<VirtAddr>,
    /// The `_KTHREAD` selected to run next.
    pub next_thread: DiagnosticValue<VirtAddr>,
    /// The idle `_KTHREAD` of the processor.
    pub idle_thread: DiagnosticValue<VirtAddr>,
    /// `_KPRCB.DpcRoutineActive`.
    pub dpc_routine_active: DiagnosticValue<u64>,
    /// `_KPRCB.InterruptCount`.
    pub interrupt_count: DiagnosticValue<u64>,
    pub processor_state: DiagnosticValue<ProcessorStateArea>,
}

/// The current IRQL of a processor (`!irql`).
#[record]
pub struct Irql {
    /// The processor number.
    pub processor: u16,
    /// The IRQL.
    pub value: DiagnosticValue<u64>,
    /// The Windows name of the level (`DISPATCH_LEVEL`, ...).
    pub level_name: DiagnosticValue<String>,
    /// A note about KD break-ins. At a KD break-in, `value` is the IRQL
    /// that the debugger sees, which can differ from the level
    /// immediately before the break-in.
    pub note: String,
}

/// One decoded AMD64 IDT gate.
#[record]
pub struct IdtGate {
    pub vector: u16,
    /// The address of the gate in the table.
    pub address: VirtAddr,
    /// The interrupt handler that the gate points to.
    pub handler: DiagnosticValue<VirtAddr>,
    /// The symbol of the handler. The diagnostic value is None if no
    /// symbol resolved.
    pub symbol: DiagnosticValue<Option<String>>,
    /// The code segment selector.
    pub selector: DiagnosticValue<u16>,
    /// The interrupt stack table index (0: none).
    pub ist: DiagnosticValue<u8>,
    /// The raw gate type.
    pub gate_type: DiagnosticValue<u8>,
    /// `interrupt`, `trap`, `task`, or `reserved`.
    pub gate_name: DiagnosticValue<String>,
    /// The descriptor privilege level.
    pub dpl: DiagnosticValue<u8>,
    pub present: DiagnosticValue<bool>,
    /// Whether the handler is in a module other than NT.
    pub non_nt_hook: DiagnosticValue<bool>,
    /// For a handler in `KiIsrThunk` (a chained interrupt), the offset of
    /// the handler in `KiIsrThunk` and the location of
    /// `_KINTERRUPT.DispatchCode`. The diagnostic value is None for other
    /// handlers.
    pub ki_isr_thunk: DiagnosticValue<Option<String>>,
}

/// The IDT of a processor (`!idt`), with one vector or the bounded full
/// table.
#[record]
pub struct Idt {
    /// The processor number.
    pub processor: u16,
    /// The address of the table.
    pub base: VirtAddr,
    /// The table limit: the table size in bytes, minus one.
    pub limit: u64,
    /// The requested vector, or None for the full table.
    pub vector: Option<u16>,
    /// Whether the descriptor is shorter than the full table.
    pub truncated: bool,
    pub entries: Vec<IdtGate>,
}

/// One decoded GDT descriptor. A system descriptor uses two slots.
#[record]
pub struct GdtDescriptor {
    /// The slot index.
    pub index: u64,
    /// The 8 raw bytes of the descriptor.
    #[record(hex)]
    pub raw: DiagnosticValue<u64>,
    /// The second slot of a system descriptor. The diagnostic value is
    /// None for other descriptors.
    #[record(hex)]
    pub high_raw: DiagnosticValue<Option<u64>>,
    /// The segment base.
    pub base: DiagnosticValue<VirtAddr>,
    /// The segment limit, in bytes.
    pub limit: DiagnosticValue<u64>,
    /// The raw type field.
    pub type_code: DiagnosticValue<u8>,
    /// `system` or `code/data`.
    pub descriptor_kind: DiagnosticValue<String>,
    /// The descriptor privilege level.
    pub dpl: DiagnosticValue<u8>,
    pub present: DiagnosticValue<bool>,
    /// The L bit: a 64-bit code segment.
    pub long_mode: DiagnosticValue<bool>,
    /// The D/B bit: 32-bit default operand size.
    pub default_size: DiagnosticValue<bool>,
    /// The G bit: the limit is in 4 KiB pages.
    pub granularity: DiagnosticValue<bool>,
}

/// The GDT of a processor and its bounded descriptors (`!gdt`).
#[record]
pub struct Gdt {
    /// The processor number.
    pub processor: u16,
    /// The address of the table.
    pub base: VirtAddr,
    /// The table limit: the table size in bytes, minus one.
    pub limit: u64,
    /// The number of slots that the limit describes, which can be larger
    /// than the number of decoded entries.
    pub entry_count: u64,
    /// Whether the table has more than 256 slots.
    pub truncated: bool,
    pub entries: Vec<GdtDescriptor>,
}

/// One `_KPRCB` feature-bit field.
#[record]
pub struct CpuFeatureBits {
    /// The `_KPRCB` field.
    pub name: String,
    #[record(hex)]
    pub value: DiagnosticValue<u64>,
}

/// The triage PRCB metadata of the dump, which ntoseye uses when it
/// cannot read the KPRCB.
#[record]
pub struct CpuTriageFallback {
    pub processor_number: u16,
    pub vendor: String,
    pub family: u16,
    /// The processor speed, in MHz.
    pub mhz: u32,
}

/// The vendor, family, model, speed, and feature bits of a processor
/// (`!cpuinfo`).
#[record]
pub struct CpuInfo {
    /// The processor number.
    pub processor: u16,
    /// The `_KPRCB` address.
    pub kprcb: DiagnosticValue<VirtAddr>,
    /// The source of the values: `_KPRCB` or `triage-dump PRCB metadata`.
    pub source: String,
    /// The vendor string (`GenuineIntel`, ...).
    pub vendor: DiagnosticValue<String>,
    /// `_KPRCB.CpuVendor`.
    pub vendor_id: DiagnosticValue<u64>,
    pub family: DiagnosticValue<u64>,
    pub model: DiagnosticValue<u64>,
    pub stepping: DiagnosticValue<u64>,
    /// The processor speed, in MHz.
    pub mhz: DiagnosticValue<u64>,
    pub feature_bits: Vec<CpuFeatureBits>,
    /// The triage metadata, present if ntoseye could not find the KPRCB.
    pub triage_fallback: Option<CpuTriageFallback>,
}

fn descriptor(value: &DescriptorDetail) -> DescriptorRegister {
    DescriptorRegister {
        base: value.base,
        limit: value.limit,
    }
}

fn special_registers(value: &SpecialRegistersDetail) -> SpecialRegistersArea {
    SpecialRegistersArea {
        address: value.address,
        size: value.size,
        name: value.name.clone(),
    }
}

fn processor_state(value: &ProcessorStateDetail) -> ProcessorStateArea {
    ProcessorStateArea {
        address: value.address,
        size: value.size,
        name: value.name.clone(),
        context_frame: value.context_frame.clone(),
        special_registers: value.special_registers.map(special_registers),
    }
}

/// KPCR/KPRCB inspector.
pub fn pcr(detail: &PcrDetail) -> Pcr {
    Pcr {
        processor: detail.processor,
        kpcr: detail.kpcr.clone(),
        kprcb: detail.kprcb,
        kd_version_block: detail.kd_version_block.clone(),
        current_prcb: detail.current_prcb.clone(),
        irql: detail.irql.clone(),
        self_pcr: detail.self_pcr.clone(),
        current_thread: detail.current_thread.clone(),
        next_thread: detail.next_thread.clone(),
        idle_thread: detail.idle_thread.clone(),
        idtr: detail.idtr.map(descriptor),
        gdtr: detail.gdtr.map(descriptor),
        tss_base: detail.tss_base.clone(),
    }
}

/// KPRCB inspector.
pub fn prcb(detail: &PrcbDetail) -> Prcb {
    Prcb {
        processor: detail.processor,
        kprcb: detail.kprcb,
        number: detail.number.clone(),
        current_thread: detail.current_thread.clone(),
        next_thread: detail.next_thread.clone(),
        idle_thread: detail.idle_thread.clone(),
        dpc_routine_active: detail.dpc_routine_active.clone(),
        interrupt_count: detail.interrupt_count.clone(),
        processor_state: detail.processor_state.map(processor_state),
    }
}

/// IRQL inspector.
pub fn irql(detail: &IrqlDetail) -> Irql {
    Irql {
        processor: detail.processor,
        value: detail.value.clone(),
        level_name: detail.level_name.map(String::clone),
        note: detail.note.clone(),
    }
}

fn idt_entry(detail: &IdtEntryDetail) -> IdtGate {
    IdtGate {
        vector: detail.vector,
        address: detail.address,
        handler: detail.handler.clone(),
        symbol: detail.symbol.map(Option::clone),
        selector: detail.selector.clone(),
        ist: detail.ist.clone(),
        gate_type: detail.gate_type.clone(),
        gate_name: detail.gate_name.map(String::clone),
        dpl: detail.dpl.clone(),
        present: detail.present.clone(),
        non_nt_hook: detail.non_nt_hook.clone(),
        ki_isr_thunk: detail.ki_isr_thunk.map(Option::clone),
    }
}

/// IDT table inspector.
pub fn idt(detail: &IdtDetail) -> Idt {
    Idt {
        processor: detail.processor,
        base: detail.base,
        limit: detail.limit,
        vector: detail.vector,
        truncated: detail.truncated,
        entries: detail.entries.iter().map(idt_entry).collect(),
    }
}

fn gdt_entry(detail: &GdtEntryDetail) -> GdtDescriptor {
    GdtDescriptor {
        index: detail.index,
        raw: detail.raw.clone(),
        high_raw: detail.high_raw.clone(),
        base: detail.base.clone(),
        limit: detail.limit.clone(),
        type_code: detail.type_code.clone(),
        descriptor_kind: detail.descriptor_kind.map(String::clone),
        dpl: detail.dpl.clone(),
        present: detail.present.clone(),
        long_mode: detail.long_mode.clone(),
        default_size: detail.default_size.clone(),
        granularity: detail.granularity.clone(),
    }
}

/// GDT table inspector.
pub fn gdt(detail: &GdtDetail) -> Gdt {
    Gdt {
        processor: detail.processor,
        base: detail.base,
        limit: detail.limit,
        entry_count: detail.entry_count,
        truncated: detail.truncated,
        entries: detail.entries.iter().map(gdt_entry).collect(),
    }
}

fn feature_bits(detail: &FeatureBitsDetail) -> CpuFeatureBits {
    CpuFeatureBits {
        name: detail.name.clone(),
        value: detail.value.clone(),
    }
}

fn triage_fallback(detail: &CpuTriageInfo) -> CpuTriageFallback {
    CpuTriageFallback {
        processor_number: detail.processor_number,
        vendor: detail.vendor.clone(),
        family: detail.family,
        mhz: detail.mhz,
    }
}

/// CPU information inspector.
pub fn cpuinfo(detail: &CpuInfoDetail) -> CpuInfo {
    CpuInfo {
        processor: detail.processor,
        kprcb: detail.kprcb.clone(),
        source: detail.source.clone(),
        vendor: detail.vendor.map(String::clone),
        vendor_id: detail.vendor_id.clone(),
        family: detail.family.clone(),
        model: detail.model.clone(),
        stepping: detail.stepping.clone(),
        mhz: detail.mhz.clone(),
        feature_bits: detail.feature_bits.iter().map(feature_bits).collect(),
        triage_fallback: detail.triage_fallback.as_ref().map(triage_fallback),
    }
}
