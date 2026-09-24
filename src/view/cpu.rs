//! cpu: [`View`] builders for the structured inspectors.

use super::{View, diagnostic};
use crate::target::cpu::{
    CpuFeatureBits, CpuInfoDetail, CpuTriageInfo, DescriptorDetail, GdtDetail, GdtEntryDetail,
    IdtDetail, IdtEntryDetail, IrqlDetail, PcrDetail, PrcbDetail, ProcessorStateDetail,
    SpecialRegistersDetail,
};

fn descriptor(value: &DescriptorDetail) -> View {
    View::Object(vec![
        ("base", View::Hex(value.base.0)),
        ("limit", View::Num(value.limit)),
    ])
}

fn special_registers(value: &SpecialRegistersDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(value.address.0)),
        ("size", View::Num(value.size)),
        ("name", View::Str(value.name.clone())),
    ])
}

fn processor_state(value: &ProcessorStateDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(value.address.0)),
        ("size", View::Num(value.size)),
        ("name", View::Str(value.name.clone())),
        (
            "context_frame",
            diagnostic(&value.context_frame, |address| View::Hex(address.0)),
        ),
        (
            "special_registers",
            diagnostic(&value.special_registers, special_registers),
        ),
    ])
}

/// KPCR/KPRCB inspector; top-level keys: processor, kpcr, kprcb,
/// kd_version_block, current_prcb, irql, self_pcr, current_thread, next_thread,
/// idle_thread, idtr, gdtr, tss_base.
pub fn pcr(detail: &PcrDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        (
            "kpcr",
            diagnostic(&detail.kpcr, |address| View::Hex(address.0)),
        ),
        ("kprcb", View::Hex(detail.kprcb.0)),
        (
            "kd_version_block",
            diagnostic(&detail.kd_version_block, |address| View::Hex(address.0)),
        ),
        (
            "current_prcb",
            diagnostic(&detail.current_prcb, |address| View::Hex(address.0)),
        ),
        ("irql", diagnostic(&detail.irql, |value| View::Num(*value))),
        (
            "self_pcr",
            diagnostic(&detail.self_pcr, |address| View::Hex(address.0)),
        ),
        (
            "current_thread",
            diagnostic(&detail.current_thread, |address| View::Hex(address.0)),
        ),
        (
            "next_thread",
            diagnostic(&detail.next_thread, |address| View::Hex(address.0)),
        ),
        (
            "idle_thread",
            diagnostic(&detail.idle_thread, |address| View::Hex(address.0)),
        ),
        ("idtr", diagnostic(&detail.idtr, descriptor)),
        ("gdtr", diagnostic(&detail.gdtr, descriptor)),
        (
            "tss_base",
            diagnostic(&detail.tss_base, |address| View::Hex(address.0)),
        ),
    ])
}

/// KPRCB inspector; top-level keys: processor, kprcb, number, current_thread,
/// next_thread, idle_thread, dpc_routine_active, interrupt_count,
/// processor_state.
pub fn prcb(detail: &PrcbDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        ("kprcb", View::Hex(detail.kprcb.0)),
        (
            "number",
            diagnostic(&detail.number, |value| View::Num(*value)),
        ),
        (
            "current_thread",
            diagnostic(&detail.current_thread, |address| View::Hex(address.0)),
        ),
        (
            "next_thread",
            diagnostic(&detail.next_thread, |address| View::Hex(address.0)),
        ),
        (
            "idle_thread",
            diagnostic(&detail.idle_thread, |address| View::Hex(address.0)),
        ),
        (
            "dpc_routine_active",
            diagnostic(&detail.dpc_routine_active, |value| View::Num(*value)),
        ),
        (
            "interrupt_count",
            diagnostic(&detail.interrupt_count, |value| View::Num(*value)),
        ),
        (
            "processor_state",
            diagnostic(&detail.processor_state, processor_state),
        ),
    ])
}

/// IRQL inspector; top-level keys: processor, value, level_name, note.
pub fn irql(detail: &IrqlDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        (
            "value",
            diagnostic(&detail.value, |value| View::Num(*value)),
        ),
        (
            "level_name",
            diagnostic(&detail.level_name, |name| View::Str(name.clone())),
        ),
        ("note", View::Str(detail.note.clone())),
    ])
}

/// One IDT entry; top-level keys: vector, address, handler, symbol, selector,
/// ist, gate_type, gate_name, dpl, present, non_nt_hook, ki_isr_thunk.
pub fn idt_entry(detail: &IdtEntryDetail) -> View {
    View::Object(vec![
        ("vector", View::Num(u64::from(detail.vector))),
        ("address", View::Hex(detail.address.0)),
        (
            "handler",
            diagnostic(&detail.handler, |address| View::Hex(address.0)),
        ),
        (
            "symbol",
            diagnostic(&detail.symbol, |symbol| View::OptStr(symbol.clone())),
        ),
        (
            "selector",
            diagnostic(&detail.selector, |selector| View::Num(u64::from(*selector))),
        ),
        (
            "ist",
            diagnostic(&detail.ist, |ist| View::Num(u64::from(*ist))),
        ),
        (
            "gate_type",
            diagnostic(&detail.gate_type, |gate_type| {
                View::Num(u64::from(*gate_type))
            }),
        ),
        (
            "gate_name",
            diagnostic(&detail.gate_name, |name| View::Str(name.clone())),
        ),
        (
            "dpl",
            diagnostic(&detail.dpl, |dpl| View::Num(u64::from(*dpl))),
        ),
        (
            "present",
            diagnostic(&detail.present, |present| View::Bool(*present)),
        ),
        (
            "non_nt_hook",
            diagnostic(&detail.non_nt_hook, |hook| View::Bool(*hook)),
        ),
        (
            "ki_isr_thunk",
            diagnostic(&detail.ki_isr_thunk, |hint| View::OptStr(hint.clone())),
        ),
    ])
}

/// IDT table inspector; top-level keys: processor, base, limit, vector,
/// truncated, entries.
pub fn idt(detail: &IdtDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        ("base", View::Hex(detail.base.0)),
        ("limit", View::Num(detail.limit)),
        (
            "vector",
            detail
                .vector
                .map_or(View::Null, |vector| View::Num(u64::from(vector))),
        ),
        ("truncated", View::Bool(detail.truncated)),
        (
            "entries",
            View::List(detail.entries.iter().map(idt_entry).collect()),
        ),
    ])
}

/// One GDT entry; top-level keys: index, raw, high_raw, base, limit,
/// type_code, descriptor_kind, dpl, present, long_mode, default_size,
/// granularity.
pub fn gdt_entry(detail: &GdtEntryDetail) -> View {
    View::Object(vec![
        ("index", View::Num(detail.index)),
        ("raw", diagnostic(&detail.raw, |raw| View::Hex(*raw))),
        (
            "high_raw",
            diagnostic(&detail.high_raw, |raw| raw.map_or(View::Null, View::Hex)),
        ),
        (
            "base",
            diagnostic(&detail.base, |address| View::Hex(address.0)),
        ),
        (
            "limit",
            diagnostic(&detail.limit, |limit| View::Num(*limit)),
        ),
        (
            "type_code",
            diagnostic(&detail.type_code, |type_code| {
                View::Num(u64::from(*type_code))
            }),
        ),
        (
            "descriptor_kind",
            diagnostic(&detail.descriptor_kind, |kind| View::Str(kind.clone())),
        ),
        (
            "dpl",
            diagnostic(&detail.dpl, |dpl| View::Num(u64::from(*dpl))),
        ),
        (
            "present",
            diagnostic(&detail.present, |present| View::Bool(*present)),
        ),
        (
            "long_mode",
            diagnostic(&detail.long_mode, |long_mode| View::Bool(*long_mode)),
        ),
        (
            "default_size",
            diagnostic(&detail.default_size, |default_size| {
                View::Bool(*default_size)
            }),
        ),
        (
            "granularity",
            diagnostic(&detail.granularity, |granularity| View::Bool(*granularity)),
        ),
    ])
}

/// GDT table inspector; top-level keys: processor, base, limit, entry_count,
/// truncated, entries.
pub fn gdt(detail: &GdtDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        ("base", View::Hex(detail.base.0)),
        ("limit", View::Num(detail.limit)),
        ("entry_count", View::Num(detail.entry_count)),
        ("truncated", View::Bool(detail.truncated)),
        (
            "entries",
            View::List(detail.entries.iter().map(gdt_entry).collect()),
        ),
    ])
}

fn feature_bits(detail: &CpuFeatureBits) -> View {
    View::Object(vec![
        ("name", View::Str(detail.name.clone())),
        (
            "value",
            diagnostic(&detail.value, |value| View::Hex(*value)),
        ),
    ])
}

fn triage_fallback(detail: &CpuTriageInfo) -> View {
    View::Object(vec![
        (
            "processor_number",
            View::Num(u64::from(detail.processor_number)),
        ),
        ("vendor", View::Str(detail.vendor.clone())),
        ("family", View::Num(u64::from(detail.family))),
        ("mhz", View::Num(u64::from(detail.mhz))),
    ])
}

/// CPU information inspector; top-level keys: processor, kprcb, source, vendor,
/// vendor_id, family, model, stepping, mhz, feature_bits, triage_fallback.
pub fn cpuinfo(detail: &CpuInfoDetail) -> View {
    View::Object(vec![
        ("processor", View::Num(u64::from(detail.processor))),
        (
            "kprcb",
            diagnostic(&detail.kprcb, |address| View::Hex(address.0)),
        ),
        ("source", View::Str(detail.source.clone())),
        (
            "vendor",
            diagnostic(&detail.vendor, |vendor| View::Str(vendor.clone())),
        ),
        (
            "vendor_id",
            diagnostic(&detail.vendor_id, |value| View::Num(*value)),
        ),
        (
            "family",
            diagnostic(&detail.family, |value| View::Num(*value)),
        ),
        (
            "model",
            diagnostic(&detail.model, |value| View::Num(*value)),
        ),
        (
            "stepping",
            diagnostic(&detail.stepping, |value| View::Num(*value)),
        ),
        ("mhz", diagnostic(&detail.mhz, |value| View::Num(*value))),
        (
            "feature_bits",
            View::List(detail.feature_bits.iter().map(feature_bits).collect()),
        ),
        (
            "triage_fallback",
            detail
                .triage_fallback
                .as_ref()
                .map_or(View::Null, triage_fallback),
        ),
    ])
}
