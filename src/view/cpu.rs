//! cpu: [`View`] builders for the structured inspectors.

use super::shape::{Diag, Hex, shapes};
use crate::target::cpu::{
    CpuFeatureBits as FeatureBitsDetail, CpuInfoDetail, CpuTriageInfo, DescriptorDetail, GdtDetail,
    GdtEntryDetail, IdtDetail, IdtEntryDetail, IrqlDetail, PcrDetail, PrcbDetail,
    ProcessorStateDetail, SpecialRegistersDetail,
};
use crate::types::VirtAddr;

shapes! {
    /// A descriptor-table register (IDTR/GDTR).
    DescriptorRegister {
        base: VirtAddr,
        /// The table's limit: its size in bytes, minus one.
        limit: u64,
    }

    /// Where `_KSPECIAL_REGISTERS` sits in a processor state.
    SpecialRegistersArea {
        address: VirtAddr,
        /// Bytes of the structure.
        size: u64,
        /// The type name.
        name: String,
    }

    /// The `_KPROCESSOR_STATE` embedded in a `_KPRCB`.
    ProcessorStateArea {
        address: VirtAddr,
        /// Bytes of the structure.
        size: u64,
        /// The type name.
        name: String,
        /// Address of the `_CONTEXT` embedded in the processor state.
        context_frame: Diag<VirtAddr>,
        special_registers: Diag<SpecialRegistersArea>,
    }

    /// A processor's KPCR and KPRCB essentials (`!pcr`). Fields that can fail
    /// to read on their own are diagnostics.
    Pcr {
        /// The processor number.
        processor: u16,
        /// The `_KPCR` address.
        kpcr: Diag<VirtAddr>,
        /// The `_KPRCB` address.
        kprcb: VirtAddr,
        /// `_KPCR.KdVersionBlock`.
        kd_version_block: Diag<VirtAddr>,
        /// `_KPCR.CurrentPrcb`.
        current_prcb: Diag<VirtAddr>,
        /// The current IRQL.
        irql: Diag<u64>,
        /// `_KPCR.Self`.
        self_pcr: Diag<VirtAddr>,
        /// The running `_KTHREAD`.
        current_thread: Diag<VirtAddr>,
        /// The `_KTHREAD` selected to run next.
        next_thread: Diag<VirtAddr>,
        /// The processor's idle `_KTHREAD`.
        idle_thread: Diag<VirtAddr>,
        /// The interrupt descriptor table register.
        idtr: Diag<DescriptorRegister>,
        /// The global descriptor table register.
        gdtr: Diag<DescriptorRegister>,
        /// The task state segment's address.
        tss_base: Diag<VirtAddr>,
    }

    /// Selected `_KPRCB` fields of a processor (`!prcb`).
    Prcb {
        /// The processor number.
        processor: u16,
        /// The `_KPRCB` address.
        kprcb: VirtAddr,
        /// `_KPRCB.Number`.
        number: Diag<u64>,
        /// The running `_KTHREAD`.
        current_thread: Diag<VirtAddr>,
        /// The `_KTHREAD` selected to run next.
        next_thread: Diag<VirtAddr>,
        /// The processor's idle `_KTHREAD`.
        idle_thread: Diag<VirtAddr>,
        /// `_KPRCB.DpcRoutineActive`.
        dpc_routine_active: Diag<u64>,
        /// `_KPRCB.InterruptCount`.
        interrupt_count: Diag<u64>,
        processor_state: Diag<ProcessorStateArea>,
    }

    /// A processor's current IRQL (`!irql`).
    Irql {
        /// The processor number.
        processor: u16,
        /// The IRQL.
        value: Diag<u64>,
        /// The Windows name of the level (`DISPATCH_LEVEL`, ...).
        level_name: Diag<String>,
        /// At a KD break-in, the IRQL the debugger observes, which can differ
        /// from the level active just before the break-in.
        note: String,
    }

    /// One decoded AMD64 IDT gate.
    IdtGate {
        vector: u16,
        /// The gate's address in the table.
        address: VirtAddr,
        /// The interrupt handler the gate points at.
        handler: Diag<VirtAddr>,
        /// The handler's symbol; the diagnostic's value is None when none
        /// resolved.
        symbol: Diag<Option<String>>,
        /// The code segment selector.
        selector: Diag<u16>,
        /// The interrupt stack table index (0: none).
        ist: Diag<u8>,
        /// The raw gate type.
        gate_type: Diag<u8>,
        /// `interrupt`, `trap`, `task`, or `reserved`.
        gate_name: Diag<String>,
        /// The descriptor privilege level.
        dpl: Diag<u8>,
        present: Diag<bool>,
        /// Whether the handler lies in a module other than NT's.
        non_nt_hook: Diag<bool>,
        /// For a handler inside `KiIsrThunk` (a chained interrupt), its offset
        /// there and where `_KINTERRUPT.DispatchCode` sits; the diagnostic's
        /// value is None for other handlers.
        ki_isr_thunk: Diag<Option<String>>,
    }

    /// A processor's IDT: one vector, or the bounded full table (`!idt`).
    Idt {
        /// The processor number.
        processor: u16,
        /// The table's address.
        base: VirtAddr,
        /// The table's limit: its size in bytes, minus one.
        limit: u64,
        /// The one vector asked for, or None for the full table.
        vector: Option<u16>,
        /// Whether the descriptor is shorter than the full table.
        truncated: bool,
        entries: Vec<IdtGate>,
    }

    /// One decoded GDT descriptor. A system descriptor spans two slots.
    GdtDescriptor {
        /// The slot index.
        index: u64,
        /// The descriptor's raw 8 bytes.
        raw: Diag<Hex>,
        /// A system descriptor's second slot; the diagnostic's value is None
        /// for other descriptors.
        high_raw: Diag<Option<Hex>>,
        /// The segment base.
        base: Diag<VirtAddr>,
        /// The segment limit, in bytes.
        limit: Diag<u64>,
        /// The raw type field.
        type_code: Diag<u8>,
        /// `system` or `code/data`.
        descriptor_kind: Diag<String>,
        /// The descriptor privilege level.
        dpl: Diag<u8>,
        present: Diag<bool>,
        /// The L bit: a 64-bit code segment.
        long_mode: Diag<bool>,
        /// The D/B bit: 32-bit default operand size.
        default_size: Diag<bool>,
        /// The G bit: the limit counts 4 KiB pages.
        granularity: Diag<bool>,
    }

    /// A processor's GDT and its bounded descriptors (`!gdt`).
    Gdt {
        /// The processor number.
        processor: u16,
        /// The table's address.
        base: VirtAddr,
        /// The table's limit: its size in bytes, minus one.
        limit: u64,
        /// Slots the limit describes, which can exceed the entries decoded.
        entry_count: u64,
        /// Whether the table exceeds the 256-slot bound.
        truncated: bool,
        entries: Vec<GdtDescriptor>,
    }

    /// One `_KPRCB` feature-bit field.
    CpuFeatureBits {
        /// The `_KPRCB` field.
        name: String,
        value: Diag<Hex>,
    }

    /// The dump's triage PRCB metadata, used when the KPRCB is unreadable.
    CpuTriageFallback {
        processor_number: u16,
        vendor: String,
        family: u16,
        /// The processor speed, in MHz.
        mhz: u32,
    }

    /// A processor's vendor, family, model, speed, and feature bits
    /// (`!cpuinfo`).
    CpuInfo {
        /// The processor number.
        processor: u16,
        /// The `_KPRCB` address.
        kprcb: Diag<VirtAddr>,
        /// Where the values came from: `_KPRCB` or `triage-dump PRCB metadata`.
        source: String,
        /// The vendor string (`GenuineIntel`, ...).
        vendor: Diag<String>,
        /// `_KPRCB.CpuVendor`.
        vendor_id: Diag<u64>,
        family: Diag<u64>,
        model: Diag<u64>,
        stepping: Diag<u64>,
        /// The processor speed, in MHz.
        mhz: Diag<u64>,
        feature_bits: Vec<CpuFeatureBits>,
        /// Triage metadata, present when the KPRCB could not be found.
        triage_fallback: Option<CpuTriageFallback>,
    }
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
