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
        base: Hex,
        /// The table's limit: its size in bytes, minus one.
        limit: u64,
    }

    /// Where `_KSPECIAL_REGISTERS` sits in a processor state.
    SpecialRegistersArea {
        address: Hex,
        /// Bytes of the structure.
        size: u64,
        /// The type name.
        name: String,
    }

    /// The `_KPROCESSOR_STATE` embedded in a `_KPRCB`.
    ProcessorStateArea {
        address: Hex,
        /// Bytes of the structure.
        size: u64,
        /// The type name.
        name: String,
        /// Address of the `_CONTEXT` embedded in the processor state.
        context_frame: Diag<Hex>,
        special_registers: Diag<SpecialRegistersArea>,
    }

    /// A processor's KPCR and KPRCB essentials (`!pcr`). Fields that can fail
    /// to read on their own are diagnostics.
    Pcr {
        /// The processor number.
        processor: u16,
        /// The `_KPCR` address.
        kpcr: Diag<Hex>,
        /// The `_KPRCB` address.
        kprcb: Hex,
        /// `_KPCR.KdVersionBlock`.
        kd_version_block: Diag<Hex>,
        /// `_KPCR.CurrentPrcb`.
        current_prcb: Diag<Hex>,
        /// The current IRQL.
        irql: Diag<u64>,
        /// `_KPCR.Self`.
        self_pcr: Diag<Hex>,
        /// The running `_KTHREAD`.
        current_thread: Diag<Hex>,
        /// The `_KTHREAD` selected to run next.
        next_thread: Diag<Hex>,
        /// The processor's idle `_KTHREAD`.
        idle_thread: Diag<Hex>,
        /// The interrupt descriptor table register.
        idtr: Diag<DescriptorRegister>,
        /// The global descriptor table register.
        gdtr: Diag<DescriptorRegister>,
        /// The task state segment's address.
        tss_base: Diag<Hex>,
    }

    /// Selected `_KPRCB` fields of a processor (`!prcb`).
    Prcb {
        /// The processor number.
        processor: u16,
        /// The `_KPRCB` address.
        kprcb: Hex,
        /// `_KPRCB.Number`.
        number: Diag<u64>,
        /// The running `_KTHREAD`.
        current_thread: Diag<Hex>,
        /// The `_KTHREAD` selected to run next.
        next_thread: Diag<Hex>,
        /// The processor's idle `_KTHREAD`.
        idle_thread: Diag<Hex>,
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
        address: Hex,
        /// The interrupt handler the gate points at.
        handler: Diag<Hex>,
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
        base: Hex,
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
        base: Diag<Hex>,
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
        base: Hex,
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
        kprcb: Diag<Hex>,
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
        base: Hex(value.base.0),
        limit: value.limit,
    }
}

fn special_registers(value: &SpecialRegistersDetail) -> SpecialRegistersArea {
    SpecialRegistersArea {
        address: Hex(value.address.0),
        size: value.size,
        name: value.name.clone(),
    }
}

fn processor_state(value: &ProcessorStateDetail) -> ProcessorStateArea {
    ProcessorStateArea {
        address: Hex(value.address.0),
        size: value.size,
        name: value.name.clone(),
        context_frame: Diag::of(&value.context_frame, |address| Hex(address.0)),
        special_registers: Diag::of(&value.special_registers, special_registers),
    }
}

/// KPCR/KPRCB inspector.
pub fn pcr(detail: &PcrDetail) -> Pcr {
    let address = |address: &VirtAddr| Hex(address.0);
    Pcr {
        processor: detail.processor,
        kpcr: Diag::of(&detail.kpcr, address),
        kprcb: Hex(detail.kprcb.0),
        kd_version_block: Diag::of(&detail.kd_version_block, address),
        current_prcb: Diag::of(&detail.current_prcb, address),
        irql: Diag::of(&detail.irql, |value| *value),
        self_pcr: Diag::of(&detail.self_pcr, address),
        current_thread: Diag::of(&detail.current_thread, address),
        next_thread: Diag::of(&detail.next_thread, address),
        idle_thread: Diag::of(&detail.idle_thread, address),
        idtr: Diag::of(&detail.idtr, descriptor),
        gdtr: Diag::of(&detail.gdtr, descriptor),
        tss_base: Diag::of(&detail.tss_base, address),
    }
}

/// KPRCB inspector.
pub fn prcb(detail: &PrcbDetail) -> Prcb {
    let address = |address: &VirtAddr| Hex(address.0);
    Prcb {
        processor: detail.processor,
        kprcb: Hex(detail.kprcb.0),
        number: Diag::of(&detail.number, |value| *value),
        current_thread: Diag::of(&detail.current_thread, address),
        next_thread: Diag::of(&detail.next_thread, address),
        idle_thread: Diag::of(&detail.idle_thread, address),
        dpc_routine_active: Diag::of(&detail.dpc_routine_active, |value| *value),
        interrupt_count: Diag::of(&detail.interrupt_count, |value| *value),
        processor_state: Diag::of(&detail.processor_state, processor_state),
    }
}

/// IRQL inspector.
pub fn irql(detail: &IrqlDetail) -> Irql {
    Irql {
        processor: detail.processor,
        value: Diag::of(&detail.value, |value| *value),
        level_name: Diag::of(&detail.level_name, String::clone),
        note: detail.note.clone(),
    }
}

fn idt_entry(detail: &IdtEntryDetail) -> IdtGate {
    IdtGate {
        vector: detail.vector,
        address: Hex(detail.address.0),
        handler: Diag::of(&detail.handler, |address| Hex(address.0)),
        symbol: Diag::of(&detail.symbol, Option::clone),
        selector: Diag::of(&detail.selector, |selector| *selector),
        ist: Diag::of(&detail.ist, |ist| *ist),
        gate_type: Diag::of(&detail.gate_type, |gate_type| *gate_type),
        gate_name: Diag::of(&detail.gate_name, String::clone),
        dpl: Diag::of(&detail.dpl, |dpl| *dpl),
        present: Diag::of(&detail.present, |present| *present),
        non_nt_hook: Diag::of(&detail.non_nt_hook, |hook| *hook),
        ki_isr_thunk: Diag::of(&detail.ki_isr_thunk, Option::clone),
    }
}

/// IDT table inspector.
pub fn idt(detail: &IdtDetail) -> Idt {
    Idt {
        processor: detail.processor,
        base: Hex(detail.base.0),
        limit: detail.limit,
        vector: detail.vector,
        truncated: detail.truncated,
        entries: detail.entries.iter().map(idt_entry).collect(),
    }
}

fn gdt_entry(detail: &GdtEntryDetail) -> GdtDescriptor {
    GdtDescriptor {
        index: detail.index,
        raw: Diag::of(&detail.raw, |raw| Hex(*raw)),
        high_raw: Diag::of(&detail.high_raw, |raw| raw.map(Hex)),
        base: Diag::of(&detail.base, |address| Hex(address.0)),
        limit: Diag::of(&detail.limit, |limit| *limit),
        type_code: Diag::of(&detail.type_code, |type_code| *type_code),
        descriptor_kind: Diag::of(&detail.descriptor_kind, String::clone),
        dpl: Diag::of(&detail.dpl, |dpl| *dpl),
        present: Diag::of(&detail.present, |present| *present),
        long_mode: Diag::of(&detail.long_mode, |long_mode| *long_mode),
        default_size: Diag::of(&detail.default_size, |default_size| *default_size),
        granularity: Diag::of(&detail.granularity, |granularity| *granularity),
    }
}

/// GDT table inspector.
pub fn gdt(detail: &GdtDetail) -> Gdt {
    Gdt {
        processor: detail.processor,
        base: Hex(detail.base.0),
        limit: detail.limit,
        entry_count: detail.entry_count,
        truncated: detail.truncated,
        entries: detail.entries.iter().map(gdt_entry).collect(),
    }
}

fn feature_bits(detail: &FeatureBitsDetail) -> CpuFeatureBits {
    CpuFeatureBits {
        name: detail.name.clone(),
        value: Diag::of(&detail.value, |value| Hex(*value)),
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
        kprcb: Diag::of(&detail.kprcb, |address| Hex(address.0)),
        source: detail.source.clone(),
        vendor: Diag::of(&detail.vendor, String::clone),
        vendor_id: Diag::of(&detail.vendor_id, |value| *value),
        family: Diag::of(&detail.family, |value| *value),
        model: Diag::of(&detail.model, |value| *value),
        stepping: Diag::of(&detail.stepping, |value| *value),
        mhz: Diag::of(&detail.mhz, |value| *value),
        feature_bits: detail.feature_bits.iter().map(feature_bits).collect(),
        triage_fallback: detail.triage_fallback.as_ref().map(triage_fallback),
    }
}
