//! cpu: structured inspector data (shared by the REPL, Python SDK, and MCP).

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::cpu_state;
use crate::dbg_backend::DebugCapability;
use crate::error::{Error, Result};
use crate::guest::WinObject;
use crate::session::{Session, processor_index_from_backend_thread_id};
use crate::symbols::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::target::{DiagnosticValue, Target};
use crate::types::{Arch, VirtAddr};

const MAX_FIELD_BYTES: usize = 0x1000;
const IDT_VECTOR_COUNT: u16 = 256;
const MAX_GDT_ENTRIES: usize = 256;

/// A decoded descriptor-table register.
#[derive(Debug, Clone)]
pub struct DescriptorDetail {
    pub base: VirtAddr,
    pub limit: u64,
}

/// All KPCR/KPRCB fields displayed by `!pcr`.
#[derive(Debug, Clone)]
pub struct PcrDetail {
    pub processor: u16,
    pub kpcr: DiagnosticValue<VirtAddr>,
    pub kprcb: VirtAddr,
    pub kd_version_block: DiagnosticValue<VirtAddr>,
    pub current_prcb: DiagnosticValue<VirtAddr>,
    pub irql: DiagnosticValue<u64>,
    pub self_pcr: DiagnosticValue<VirtAddr>,
    pub current_thread: DiagnosticValue<VirtAddr>,
    pub next_thread: DiagnosticValue<VirtAddr>,
    pub idle_thread: DiagnosticValue<VirtAddr>,
    pub idtr: DiagnosticValue<DescriptorDetail>,
    pub gdtr: DiagnosticValue<DescriptorDetail>,
    pub tss_base: DiagnosticValue<VirtAddr>,
}

/// Processor-control-block fields displayed by `!prcb`.
#[derive(Debug, Clone)]
pub struct PrcbDetail {
    pub processor: u16,
    pub kprcb: VirtAddr,
    pub number: DiagnosticValue<u64>,
    pub current_thread: DiagnosticValue<VirtAddr>,
    pub next_thread: DiagnosticValue<VirtAddr>,
    pub idle_thread: DiagnosticValue<VirtAddr>,
    pub dpc_routine_active: DiagnosticValue<u64>,
    pub interrupt_count: DiagnosticValue<u64>,
    pub processor_state: DiagnosticValue<ProcessorStateDetail>,
}

/// Nested `_KPROCESSOR_STATE` data shown by `!prcb`.
#[derive(Debug, Clone)]
pub struct ProcessorStateDetail {
    pub address: VirtAddr,
    pub size: u64,
    pub name: String,
    pub context_frame: DiagnosticValue<VirtAddr>,
    pub special_registers: DiagnosticValue<SpecialRegistersDetail>,
}

/// Nested `_KSPECIAL_REGISTERS` location shown by `!prcb`.
#[derive(Debug, Clone)]
pub struct SpecialRegistersDetail {
    pub address: VirtAddr,
    pub size: u64,
    pub name: String,
}

/// Current IRQL and its architecture-specific Windows level name.
#[derive(Debug, Clone)]
pub struct IrqlDetail {
    pub processor: u16,
    pub value: DiagnosticValue<u64>,
    pub level_name: DiagnosticValue<String>,
    /// At a KD break-in this is the debugger-observed IRQL, which can differ
    /// from the level that was active immediately before the break-in.
    pub note: String,
}

/// One decoded AMD64 interrupt-gate entry.
#[derive(Debug, Clone)]
pub struct IdtEntryDetail {
    pub vector: u16,
    pub address: VirtAddr,
    pub handler: DiagnosticValue<VirtAddr>,
    pub symbol: DiagnosticValue<Option<String>>,
    pub selector: DiagnosticValue<u16>,
    pub ist: DiagnosticValue<u8>,
    pub gate_type: DiagnosticValue<u8>,
    pub gate_name: DiagnosticValue<String>,
    pub dpl: DiagnosticValue<u8>,
    pub present: DiagnosticValue<bool>,
    pub non_nt_hook: DiagnosticValue<bool>,
    pub ki_isr_thunk: DiagnosticValue<Option<String>>,
}

/// An IDT descriptor and one vector or the bounded full table.
#[derive(Debug, Clone)]
pub struct IdtDetail {
    pub processor: u16,
    pub base: VirtAddr,
    pub limit: u64,
    pub vector: Option<u16>,
    pub truncated: bool,
    pub entries: Vec<IdtEntryDetail>,
}

/// One decoded GDT descriptor. System descriptors consume a second raw slot,
/// retained in `high_raw` when it is available.
#[derive(Debug, Clone)]
pub struct GdtEntryDetail {
    pub index: u64,
    pub raw: DiagnosticValue<u64>,
    pub high_raw: DiagnosticValue<Option<u64>>,
    pub base: DiagnosticValue<VirtAddr>,
    pub limit: DiagnosticValue<u64>,
    pub type_code: DiagnosticValue<u8>,
    pub descriptor_kind: DiagnosticValue<String>,
    pub dpl: DiagnosticValue<u8>,
    pub present: DiagnosticValue<bool>,
    pub long_mode: DiagnosticValue<bool>,
    pub default_size: DiagnosticValue<bool>,
    pub granularity: DiagnosticValue<bool>,
}

/// A GDT descriptor and its bounded entries.
#[derive(Debug, Clone)]
pub struct GdtDetail {
    pub processor: u16,
    pub base: VirtAddr,
    pub limit: u64,
    pub entry_count: u64,
    pub truncated: bool,
    pub entries: Vec<GdtEntryDetail>,
}

/// One `_KPRCB` feature-bit field, retaining independent read failures.
#[derive(Debug, Clone)]
pub struct CpuFeatureBits {
    pub name: String,
    pub value: DiagnosticValue<u64>,
}

/// Triage PRCB metadata retained when a discovered KPRCB is unreadable.
#[derive(Debug, Clone)]
pub struct CpuTriageInfo {
    pub processor_number: u16,
    pub vendor: String,
    pub family: u16,
    pub mhz: u32,
}

/// CPU identity and feature fields gathered from `_KPRCB` or triage metadata.
#[derive(Debug, Clone)]
pub struct CpuInfoDetail {
    pub processor: u16,
    pub kprcb: DiagnosticValue<VirtAddr>,
    pub source: String,
    pub vendor: DiagnosticValue<String>,
    pub vendor_id: DiagnosticValue<u64>,
    pub family: DiagnosticValue<u64>,
    pub model: DiagnosticValue<u64>,
    pub stepping: DiagnosticValue<u64>,
    pub mhz: DiagnosticValue<u64>,
    pub feature_bits: Vec<CpuFeatureBits>,
    pub triage_fallback: Option<CpuTriageInfo>,
}

const KD_BREAKIN_NOTE: &str = "At a KD break-in, this is the debugger's observed IRQL and may differ from the level before the break-in.";

const MSRS: &[(u32, &str)] = &[
    (0x0000_0010, "TSC"),
    (0x0000_001b, "IA32_APIC_BASE"),
    (0x0000_0174, "IA32_SYSENTER_CS"),
    (0x0000_0175, "IA32_SYSENTER_ESP"),
    (0x0000_0176, "IA32_SYSENTER_EIP"),
    (0xc000_0080, "IA32_EFER"),
    (0xc000_0081, "IA32_STAR"),
    (0xc000_0082, "IA32_LSTAR"),
    (0xc000_0100, "IA32_FS_BASE"),
    (0xc000_0101, "IA32_GS_BASE"),
    (0xc000_0102, "IA32_KERNEL_GS_BASE"),
];

/// Return the conventional name for a known MSR number.
pub fn msr_name(msr: u32) -> Option<&'static str> {
    MSRS.iter()
        .find_map(|(value, name)| (*value == msr).then_some(*name))
}

/// Parse a conventional `IA32_*`/`MSR_IA32_*` (or short `TSC`) name.
/// Numeric expressions are intentionally handled by the REPL, not here.
pub fn parse_msr_name(name: &str) -> Option<u32> {
    let normalized = name.trim().to_ascii_uppercase().replace('-', "_");
    let normalized = normalized.strip_prefix("MSR_").unwrap_or(&normalized);
    let normalized = normalized.strip_prefix("IA32_").unwrap_or(normalized);
    MSRS.iter()
        .find(|(_, candidate)| normalized == candidate.strip_prefix("IA32_").unwrap_or(candidate))
        .map(|(value, _)| *value)
}

fn kernel(target: &Target) -> Result<&WinObject> {
    Ok(&target.guest()?.ntoskrnl)
}

fn layout(target: &Target, name: &str) -> Result<Arc<TypeInfo>> {
    kernel(target)?.types().layout(name)
}

fn lookup_field<'a>(layout: &'a TypeInfo, names: &[&str]) -> Result<(&'a str, &'a FieldInfo)> {
    names
        .iter()
        .find_map(|name| layout.fields.get_key_value(*name))
        .map(|(name, field)| (name.as_str(), field))
        .ok_or_else(|| Error::FieldNotFound(names.first().copied().unwrap_or("<unknown>").into()))
}

fn field_bytes(
    target: &Target,
    layout: &Arc<TypeInfo>,
    base: VirtAddr,
    names: &[&str],
) -> Result<Vec<u8>> {
    let (name, _) = lookup_field(layout, names)?;
    kernel(target)?
        .types()
        .struct_with_layout(Arc::clone(layout), base)
        .read_field_bytes(name, MAX_FIELD_BYTES)
}

fn field_u64(
    target: &Target,
    layout: &Arc<TypeInfo>,
    base: VirtAddr,
    names: &[&str],
) -> Result<u64> {
    let (name, _) = lookup_field(layout, names)?;
    kernel(target)?
        .types()
        .struct_with_layout(Arc::clone(layout), base)
        .read_uint(name)
}

fn field_string(
    target: &Target,
    layout: &Arc<TypeInfo>,
    base: VirtAddr,
    names: &[&str],
) -> Result<String> {
    let bytes = field_bytes(target, layout, base, names)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).trim().to_string())
}

fn nested_field(
    target: &Target,
    parent: &Arc<TypeInfo>,
    base: VirtAddr,
    names: &[&str],
    fallback_type: &str,
) -> Result<(Arc<TypeInfo>, VirtAddr)> {
    let (name, field) = lookup_field(parent, names)?;
    let (type_name, pointer) = match &field.type_data {
        ParsedType::Struct(name) | ParsedType::Union(name) => (name.as_str(), false),
        ParsedType::Pointer(inner) => match inner.as_ref() {
            ParsedType::Struct(name) | ParsedType::Union(name) => (name.as_str(), true),
            _ => (fallback_type, true),
        },
        _ => (fallback_type, false),
    };
    let address = base + u64::from(field.offset);
    let address = if pointer {
        let pointer: VirtAddr = kernel(target)?
            .types()
            .struct_with_layout(Arc::clone(parent), base)
            .read_field(name)?;
        if pointer.is_zero() {
            return Err(Error::DebugInfo(format!("field {} is null", names[0])));
        }
        pointer
    } else {
        address
    };
    Ok((
        layout(target, type_name).or_else(|_| layout(target, fallback_type))?,
        address,
    ))
}

#[derive(Clone, Debug)]
struct CpuLocation {
    processor: u16,
    kpcr: DiagnosticValue<VirtAddr>,
    kprcb: VirtAddr,
}

fn cpu_location(target: &Target, processor: u16) -> Result<CpuLocation> {
    let kprcb = cpu_state::kprcb_for_processor(target, processor)?;
    Ok(CpuLocation {
        processor,
        // A missing ARM64 `_KPCR.Prcb` field must not hide the independently
        // addressable KPRCB.
        kpcr: DiagnosticValue::from_result(cpu_state::kpcr_for_processor(target, processor)),
        kprcb,
    })
}

fn addr_value(value: Result<u64>) -> DiagnosticValue<VirtAddr> {
    DiagnosticValue::from_result(value.map(VirtAddr))
}

fn descriptor_from_layout(
    target: &Target,
    type_name: &str,
    base: VirtAddr,
    base_names: &[&str],
    limit_names: &[&str],
) -> Result<DescriptorDetail> {
    let layout = layout(target, type_name)?;
    Ok(DescriptorDetail {
        base: VirtAddr(field_u64(target, &layout, base, base_names)?),
        limit: field_u64(target, &layout, base, limit_names)?,
    })
}

fn descriptor_from_prcb(
    target: &Target,
    prcb: VirtAddr,
    names: &[&str],
) -> Result<DescriptorDetail> {
    let prcb_layout = layout(target, "_KPRCB")?;
    let (processor_state, processor_state_base) = nested_field(
        target,
        &prcb_layout,
        prcb,
        &["ProcessorState"],
        "_KPROCESSOR_STATE",
    )?;
    let (special_registers, special_registers_base) = nested_field(
        target,
        &processor_state,
        processor_state_base,
        &["SpecialRegisters"],
        "_KSPECIAL_REGISTERS",
    )?;
    let descriptor = nested_field(
        target,
        &special_registers,
        special_registers_base,
        names,
        "_KDESCRIPTOR",
    );
    match descriptor {
        Ok((descriptor_layout, descriptor_base)) => Ok(DescriptorDetail {
            base: VirtAddr(field_u64(
                target,
                &descriptor_layout,
                descriptor_base,
                &["Base", "Address"],
            )?),
            limit: field_u64(
                target,
                &descriptor_layout,
                descriptor_base,
                &["Limit", "Length"],
            )?,
        }),
        Err(nested_error) => {
            // Some public/skeletal PDBs describe KDESCRIPTOR as an opaque
            // aggregate. Its AMD64 wire layout is stable: Limit at +6 and
            // Base at +8 (or the compact 10-byte form).
            let bytes = match field_bytes(target, &special_registers, special_registers_base, names)
            {
                Ok(bytes) => bytes,
                Err(_) => return Err(nested_error),
            };
            if bytes.len() >= 16 {
                Ok(DescriptorDetail {
                    base: VirtAddr(le_uint(&bytes[8..16])),
                    limit: le_uint(&bytes[6..8]),
                })
            } else if bytes.len() >= 10 {
                Ok(DescriptorDetail {
                    base: VirtAddr(le_uint(&bytes[2..10])),
                    limit: le_uint(&bytes[0..2]),
                })
            } else {
                Err(nested_error)
            }
        }
    }
}

fn descriptor_from_target(
    target: &Target,
    location: &CpuLocation,
    names: &[&str],
    direct_base_names: &[&str],
    direct_limit_names: &[&str],
) -> Result<DescriptorDetail> {
    descriptor_from_prcb(target, location.kprcb, names).or_else(|_| {
        let kpcr = match &location.kpcr {
            DiagnosticValue::Available(kpcr) => *kpcr,
            DiagnosticValue::Unavailable(error) => {
                return Err(Error::DebugInfo(error.clone()));
            }
        };
        descriptor_from_layout(target, "_KPCR", kpcr, direct_base_names, direct_limit_names)
    })
}

fn target_descriptor_value(
    target: &Target,
    location: &CpuLocation,
    names: &[&str],
    direct_base_names: &[&str],
    direct_limit_names: &[&str],
) -> DiagnosticValue<DescriptorDetail> {
    DiagnosticValue::from_result(descriptor_from_target(
        target,
        location,
        names,
        direct_base_names,
        direct_limit_names,
    ))
}

fn validate_idt_vector(vector: Option<u16>) -> Result<()> {
    if let Some(vector) = vector
        && vector >= IDT_VECTOR_COUNT
    {
        return Err(Error::DebugInfo(format!(
            "IDT vector {vector:#x} is outside 0..255"
        )));
    }
    Ok(())
}

fn tss_base(target: &Target, location: &CpuLocation) -> DiagnosticValue<VirtAddr> {
    let value = match &location.kpcr {
        DiagnosticValue::Available(kpcr) => layout(target, "_KPCR")
            .and_then(|kpcr_layout| field_u64(target, &kpcr_layout, *kpcr, &["TssBase", "Tss"]))
            .or_else(|_| {
                layout(target, "_KPRCB").and_then(|prcb_layout| {
                    field_u64(target, &prcb_layout, location.kprcb, &["TssBase", "Tss"])
                })
            }),
        DiagnosticValue::Unavailable(_) => layout(target, "_KPRCB").and_then(|prcb_layout| {
            field_u64(target, &prcb_layout, location.kprcb, &["TssBase", "Tss"])
        }),
    };
    addr_value(value)
}

impl Target {
    /// Decode `_KPCR`/`_KPRCB` essentials for `processor`. Address, IRQL, and
    /// thread fields become unavailable when their individual layout or memory
    /// reads fail; descriptor values likewise retain nested PDB/read errors.
    pub fn inspect_pcr(&self, processor: u16) -> Result<PcrDetail> {
        let location = cpu_location(self, processor)?;
        let kpcr_fields = match &location.kpcr {
            DiagnosticValue::Available(kpcr) => layout(self, "_KPCR").ok().map(|kpcr_layout| {
                (
                    addr_value(field_u64(self, &kpcr_layout, *kpcr, &["KdVersionBlock"])),
                    addr_value(field_u64(self, &kpcr_layout, *kpcr, &["CurrentPrcb"])),
                    DiagnosticValue::from_result(field_u64(
                        self,
                        &kpcr_layout,
                        *kpcr,
                        &["Irql", "CurrentIrql"],
                    )),
                    addr_value(field_u64(self, &kpcr_layout, *kpcr, &["Self", "SelfPcr"])),
                )
            }),
            DiagnosticValue::Unavailable(_) => None,
        };
        let (kd_version_block, current_prcb, irql, self_pcr) = kpcr_fields.unwrap_or_else(|| {
            let error = match &location.kpcr {
                DiagnosticValue::Available(_) => "_KPCR layout unavailable".to_string(),
                DiagnosticValue::Unavailable(error) => error.clone(),
            };
            (
                DiagnosticValue::Unavailable(error.clone()),
                DiagnosticValue::Unavailable(error.clone()),
                DiagnosticValue::Unavailable(error.clone()),
                DiagnosticValue::Unavailable(error),
            )
        });
        let prcb_fields = layout(self, "_KPRCB").ok().map(|prcb_layout| {
            (
                addr_value(field_u64(
                    self,
                    &prcb_layout,
                    location.kprcb,
                    &["CurrentThread"],
                )),
                addr_value(field_u64(
                    self,
                    &prcb_layout,
                    location.kprcb,
                    &["NextThread"],
                )),
                addr_value(field_u64(
                    self,
                    &prcb_layout,
                    location.kprcb,
                    &["IdleThread"],
                )),
            )
        });
        let (current_thread, next_thread, idle_thread) = prcb_fields.unwrap_or_else(|| {
            let error = "_KPRCB layout unavailable".to_string();
            (
                DiagnosticValue::Unavailable(error.clone()),
                DiagnosticValue::Unavailable(error.clone()),
                DiagnosticValue::Unavailable(error),
            )
        });
        Ok(PcrDetail {
            processor: location.processor,
            kpcr: location.kpcr.clone(),
            kprcb: location.kprcb,
            kd_version_block,
            current_prcb,
            irql,
            self_pcr,
            current_thread,
            next_thread,
            idle_thread,
            idtr: target_descriptor_value(
                self,
                &location,
                &["Idtr", "IDTR"],
                &["IdtBase", "IDTBase"],
                &["IdtLimit", "IDTLimit"],
            ),
            gdtr: target_descriptor_value(
                self,
                &location,
                &["Gdtr", "GDTR"],
                &["GdtBase", "GDTBase"],
                &["GdtLimit", "GDTLimit"],
            ),
            tss_base: tss_base(self, &location),
        })
    }

    /// Decode selected `_KPRCB` fields and nested ProcessorState metadata.
    /// Every scalar read is retained as a `DiagnosticValue` so partial PDBs do
    /// not make unrelated processor counters disappear.
    pub fn inspect_prcb(&self, processor: u16) -> Result<PrcbDetail> {
        let location = cpu_location(self, processor)?;
        let prcb_layout = layout(self, "_KPRCB")?;
        let processor_state = match nested_field(
            self,
            &prcb_layout,
            location.kprcb,
            &["ProcessorState"],
            "_KPROCESSOR_STATE",
        ) {
            Ok((state_layout, state_base)) => {
                let special_registers = match nested_field(
                    self,
                    &state_layout,
                    state_base,
                    &["SpecialRegisters"],
                    "_KSPECIAL_REGISTERS",
                ) {
                    Ok((special_layout, special_base)) => {
                        DiagnosticValue::Available(SpecialRegistersDetail {
                            address: special_base,
                            size: special_layout.size as u64,
                            name: special_layout.name.clone(),
                        })
                    }
                    Err(error) => DiagnosticValue::Unavailable(error.to_string()),
                };
                DiagnosticValue::Available(ProcessorStateDetail {
                    address: state_base,
                    size: state_layout.size as u64,
                    name: state_layout.name.clone(),
                    context_frame: addr_value(field_u64(
                        self,
                        &state_layout,
                        state_base,
                        &["ContextFrame"],
                    )),
                    special_registers,
                })
            }
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };
        Ok(PrcbDetail {
            processor: location.processor,
            kprcb: location.kprcb,
            number: DiagnosticValue::from_result(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["Number", "ProcessorNumber"],
            )),
            current_thread: addr_value(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["CurrentThread"],
            )),
            next_thread: addr_value(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["NextThread"],
            )),
            idle_thread: addr_value(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["IdleThread"],
            )),
            dpc_routine_active: DiagnosticValue::from_result(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["DpcRoutineActive"],
            )),
            interrupt_count: DiagnosticValue::from_result(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &["InterruptCount"],
            )),
            processor_state,
        })
    }

    /// Decode current IRQL from `_KPCR` and `_KPRCB`, preferring the KPCR
    /// field. `value` and `level_name` are unavailable together only when both
    /// memory/layout paths fail; `note` records KD break-in semantics.
    pub fn inspect_irql(&self, processor: u16) -> Result<IrqlDetail> {
        let location = cpu_location(self, processor)?;
        let value = match &location.kpcr {
            DiagnosticValue::Available(kpcr) => layout(self, "_KPCR")
                .and_then(|kpcr_layout| {
                    field_u64(self, &kpcr_layout, *kpcr, &["Irql", "CurrentIrql"])
                })
                .or_else(|_| {
                    layout(self, "_KPRCB").and_then(|prcb_layout| {
                        field_u64(self, &prcb_layout, location.kprcb, &["CurrentIrql", "Irql"])
                    })
                }),
            DiagnosticValue::Unavailable(_) => layout(self, "_KPRCB").and_then(|prcb_layout| {
                field_u64(self, &prcb_layout, location.kprcb, &["CurrentIrql", "Irql"])
            }),
        };
        let value = DiagnosticValue::from_result(value);
        let level_name = match &value {
            DiagnosticValue::Available(value) => {
                DiagnosticValue::Available(irql_name(self.arch(), *value).to_string())
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        Ok(IrqlDetail {
            processor: location.processor,
            value,
            level_name,
            note: KD_BREAKIN_NOTE.to_string(),
        })
    }

    /// Decode one IDT vector or all 256 AMD64 entries using a descriptor read
    /// from target memory. Handler, selector, gate, presence, hook, and symbol
    /// fields carry individual byte/symbol failures; `truncated` reports a
    /// descriptor shorter than the full bounded table.
    pub fn inspect_idt(&self, processor: u16, vector: Option<u16>) -> Result<IdtDetail> {
        if self.arch() == Arch::Arm64 {
            return Err(Error::DebugInfo(
                "!idt is not defined on ARM64 targets".into(),
            ));
        }
        validate_idt_vector(vector)?;
        let location = cpu_location(self, processor)?;
        let descriptor = descriptor_from_target(
            self,
            &location,
            &["Idtr", "IDTR"],
            &["IdtBase", "IDTBase"],
            &["IdtLimit", "IDTLimit"],
        )?;
        Ok(decode_idt(self, location.processor, descriptor, vector))
    }

    /// Decode the bounded AMD64 GDT from a descriptor read from target memory.
    /// Raw, base, limit, type, privilege, presence, mode, and granularity
    /// fields retain individual entry read failures; `truncated` reports when
    /// the descriptor exceeds the 256-entry bound.
    pub fn inspect_gdt(&self, processor: u16) -> Result<GdtDetail> {
        if self.arch() == Arch::Arm64 {
            return Err(Error::DebugInfo(
                "!gdt is not defined on ARM64 targets".into(),
            ));
        }
        let location = cpu_location(self, processor)?;
        let descriptor = descriptor_from_target(
            self,
            &location,
            &["Gdtr", "GDTR"],
            &["GdtBase", "GDTBase"],
            &["GdtLimit", "GDTLimit"],
        )?;
        Ok(decode_gdt(self, location.processor, descriptor))
    }

    /// Decode vendor, family/model/stepping, speed, and `_KPRCB` feature
    /// fields. Each PDB/memory read is independent; triage PRCB metadata is
    /// used as a complete fallback when the processor block cannot be found.
    pub fn inspect_cpuinfo(&self, processor: u16) -> Result<CpuInfoDetail> {
        let location = match cpu_location(self, processor) {
            Ok(location) => location,
            Err(error) => {
                if let Some(info) = self
                    .phys
                    .dmp_info()
                    .and_then(|dump| dump.triage_prcb_info.as_ref())
                {
                    let unavailable_addr =
                        |message: &str| DiagnosticValue::Unavailable(message.to_string());
                    let unavailable_num =
                        |message: &str| DiagnosticValue::Unavailable(message.to_string());
                    return Ok(CpuInfoDetail {
                        processor: info.processor_number,
                        kprcb: unavailable_addr("KPRCB address unavailable in triage metadata"),
                        source: "triage-dump PRCB metadata".to_string(),
                        vendor: DiagnosticValue::Available(info.vendor_string.clone()),
                        vendor_id: unavailable_num("vendor id unavailable in triage metadata"),
                        family: DiagnosticValue::Available(u64::from(info.cpu_type)),
                        model: unavailable_num("model unavailable in triage metadata"),
                        stepping: unavailable_num("stepping unavailable in triage metadata"),
                        mhz: DiagnosticValue::Available(u64::from(info.mhz)),
                        feature_bits: [
                            "FeatureBits",
                            "FeatureBitsEx",
                            "ProcessorFeatures",
                            "XStateFeatures",
                        ]
                        .into_iter()
                        .map(|name| CpuFeatureBits {
                            name: name.to_string(),
                            value: unavailable_num("feature bits unavailable in triage metadata"),
                        })
                        .collect(),
                        triage_fallback: None,
                    });
                }
                return Err(error);
            }
        };
        let prcb_layout = layout(self, "_KPRCB")?;
        let vendor = DiagnosticValue::from_result(field_string(
            self,
            &prcb_layout,
            location.kprcb,
            &["VendorString", "Vendor"],
        ));
        let vendor_id = DiagnosticValue::from_result(field_u64(
            self,
            &prcb_layout,
            location.kprcb,
            &["CpuVendor", "VendorId"],
        ));
        let family = DiagnosticValue::from_result(field_u64(
            self,
            &prcb_layout,
            location.kprcb,
            &["CpuType", "CpuFamily", "Family"],
        ));
        let cpu_step = field_u64(
            self,
            &prcb_layout,
            location.kprcb,
            &["CpuStep", "Stepping", "CpuStepping"],
        );
        let (model, stepping) = match cpu_step {
            Ok(value) => (
                DiagnosticValue::Available((value >> 8) & 0xff),
                DiagnosticValue::Available(value & 0xff),
            ),
            Err(error) => {
                let error = error.to_string();
                (
                    DiagnosticValue::Unavailable(error.clone()),
                    DiagnosticValue::Unavailable(error),
                )
            }
        };
        let mhz = DiagnosticValue::from_result(field_u64(
            self,
            &prcb_layout,
            location.kprcb,
            &["MHz", "Mhz", "CurrentMHz"],
        ));
        let feature_bits = [
            "FeatureBits",
            "FeatureBitsEx",
            "ProcessorFeatures",
            "XStateFeatures",
        ]
        .into_iter()
        .map(|name| CpuFeatureBits {
            name: name.to_string(),
            value: DiagnosticValue::from_result(field_u64(
                self,
                &prcb_layout,
                location.kprcb,
                &[name],
            )),
        })
        .collect();
        let triage_fallback = if matches!(&vendor, DiagnosticValue::Unavailable(_))
            && matches!(&vendor_id, DiagnosticValue::Unavailable(_))
            && matches!(&family, DiagnosticValue::Unavailable(_))
            && matches!(&model, DiagnosticValue::Unavailable(_))
            && matches!(&stepping, DiagnosticValue::Unavailable(_))
            && matches!(&mhz, DiagnosticValue::Unavailable(_))
        {
            self.phys
                .dmp_info()
                .and_then(|dump| dump.triage_prcb_info.as_ref())
                .map(|info| CpuTriageInfo {
                    processor_number: info.processor_number,
                    vendor: info.vendor_string.clone(),
                    family: info.cpu_type,
                    mhz: info.mhz,
                })
        } else {
            None
        };
        Ok(CpuInfoDetail {
            processor: location.processor,
            kprcb: DiagnosticValue::Available(location.kprcb),
            source: "_KPRCB".to_string(),
            vendor,
            vendor_id,
            family,
            model,
            stepping,
            mhz,
            feature_bits,
            triage_fallback,
        })
    }
}

fn irql_name(arch: Arch, irql: u64) -> &'static str {
    match arch {
        Arch::Amd64 => match irql {
            0 => "PASSIVE_LEVEL",
            1 => "APC_LEVEL",
            2 => "DISPATCH_LEVEL",
            5 => "CMCI_LEVEL",
            13 => "CLOCK_LEVEL",
            14 => "IPI_LEVEL",
            15 => "HIGH_LEVEL",
            _ => "DIRQL",
        },
        Arch::Arm64 => match irql {
            0 => "PASSIVE_LEVEL",
            1 => "APC_LEVEL",
            2 => "DISPATCH_LEVEL",
            13 => "CLOCK_LEVEL",
            14 => "IPI_LEVEL",
            15 => "HIGH_LEVEL",
            _ => "DIRQL",
        },
    }
}

fn is_nt_module(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("ntoskrnl") || name.contains("ntkrnl") || name == "nt"
}

fn interrupt_chain_hint(target: &Target, handler: u64) -> Option<String> {
    let thunk = target
        .symbols
        .find_symbol_with_module(target.kernel_dtb(), "nt!KiIsrThunk")
        .ok()
        .flatten()
        .map(|(address, _)| address.0)?;
    if handler < thunk || handler - thunk >= 0x1000 {
        return None;
    }
    let dispatch = layout(target, "_KINTERRUPT").ok().and_then(|layout| {
        layout.fields.get("DispatchCode").map(|field| {
            format!(
                "KiIsrThunk (+{:#x}); _KINTERRUPT.DispatchCode offset {:#x}",
                handler - thunk,
                field.offset
            )
        })
    });
    Some(dispatch.unwrap_or_else(|| {
        "KiIsrThunk (chained interrupt; _KINTERRUPT.DispatchCode unavailable)".into()
    }))
}

fn unavailable_idt_entry(vector: u16, address: VirtAddr, error: String) -> IdtEntryDetail {
    IdtEntryDetail {
        vector,
        address,
        handler: DiagnosticValue::Unavailable(error.clone()),
        symbol: DiagnosticValue::Unavailable(error.clone()),
        selector: DiagnosticValue::Unavailable(error.clone()),
        ist: DiagnosticValue::Unavailable(error.clone()),
        gate_type: DiagnosticValue::Unavailable(error.clone()),
        gate_name: DiagnosticValue::Unavailable(error.clone()),
        dpl: DiagnosticValue::Unavailable(error.clone()),
        present: DiagnosticValue::Unavailable(error.clone()),
        non_nt_hook: DiagnosticValue::Unavailable(error.clone()),
        ki_isr_thunk: DiagnosticValue::Unavailable(error),
    }
}

fn decode_idt_entry(target: &Target, base: u64, vector: u16) -> IdtEntryDetail {
    let address = VirtAddr(base.wrapping_add(u64::from(vector) * 16));
    let mut bytes = [0u8; 16];
    let read = kernel(target).and_then(|nt| nt.memory().read_bytes(address, &mut bytes));
    let Err(error) = read else {
        let offset = u64::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            | (u64::from(u16::from_le_bytes([bytes[6], bytes[7]])) << 16)
            | (u64::from(u32::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ])) << 32);
        let selector = u16::from_le_bytes([bytes[2], bytes[3]]);
        let ist = bytes[4] & 0x7;
        let attributes = bytes[5];
        let gate_type = attributes & 0xf;
        let dpl = (attributes >> 5) & 0x3;
        let present = attributes & 0x80 != 0;
        let gate_name = match gate_type {
            0xe => "interrupt",
            0xf => "trap",
            0x5 => "task",
            _ => "reserved",
        };
        let symbol = target
            .symbols
            .format_closest_symbol_for_address(target.kernel_dtb(), VirtAddr(offset));
        let module = target
            .symbols
            .find_module_for_address(target.kernel_dtb(), VirtAddr(offset));
        let symbol_module_is_hook = symbol
            .as_deref()
            .and_then(|symbol| symbol.split_once('!'))
            .is_some_and(|(module, _)| !is_nt_module(module));
        let hook = module
            .as_ref()
            .is_some_and(|module| !is_nt_module(&module.name))
            || symbol_module_is_hook;
        return IdtEntryDetail {
            vector,
            address,
            handler: DiagnosticValue::Available(VirtAddr(offset)),
            symbol: DiagnosticValue::Available(symbol),
            selector: DiagnosticValue::Available(selector),
            ist: DiagnosticValue::Available(ist),
            gate_type: DiagnosticValue::Available(gate_type),
            gate_name: DiagnosticValue::Available(gate_name.to_string()),
            dpl: DiagnosticValue::Available(dpl),
            present: DiagnosticValue::Available(present),
            non_nt_hook: DiagnosticValue::Available(hook),
            ki_isr_thunk: DiagnosticValue::Available(interrupt_chain_hint(target, offset)),
        };
    };
    unavailable_idt_entry(vector, address, error.to_string())
}

fn decode_idt(
    target: &Target,
    processor: u16,
    descriptor: DescriptorDetail,
    vector: Option<u16>,
) -> IdtDetail {
    let vectors: Vec<u16> = vector
        .map(|vector| vec![vector])
        .unwrap_or_else(|| (0..IDT_VECTOR_COUNT).collect());
    let entries = vectors
        .into_iter()
        .map(|vector| decode_idt_entry(target, descriptor.base.0, vector))
        .collect();
    let descriptor_entries = descriptor.limit.saturating_add(1) / 16;
    let truncated = match vector {
        Some(vector) => u64::from(vector) >= descriptor_entries,
        None => descriptor.limit < (u64::from(IDT_VECTOR_COUNT) * 16 - 1),
    };
    IdtDetail {
        processor,
        base: descriptor.base,
        limit: descriptor.limit,
        vector,
        truncated,
        entries,
    }
}

fn is_system_descriptor(raw: u64) -> bool {
    let system = raw & (1 << 44) == 0;
    let typ = (raw >> 40) & 0xf;
    system && matches!(typ, 0x2 | 0x9 | 0xb)
}

fn unavailable_gdt_entry(index: usize, error: String) -> GdtEntryDetail {
    GdtEntryDetail {
        index: index as u64,
        raw: DiagnosticValue::Unavailable(error.clone()),
        high_raw: DiagnosticValue::Unavailable(error.clone()),
        base: DiagnosticValue::Unavailable(error.clone()),
        limit: DiagnosticValue::Unavailable(error.clone()),
        type_code: DiagnosticValue::Unavailable(error.clone()),
        descriptor_kind: DiagnosticValue::Unavailable(error.clone()),
        dpl: DiagnosticValue::Unavailable(error.clone()),
        present: DiagnosticValue::Unavailable(error.clone()),
        long_mode: DiagnosticValue::Unavailable(error.clone()),
        default_size: DiagnosticValue::Unavailable(error.clone()),
        granularity: DiagnosticValue::Unavailable(error),
    }
}

fn decode_gdt_entry(index: usize, raw: u64, high_raw: Result<Option<u64>>) -> GdtEntryDetail {
    let high_value = match high_raw.as_ref() {
        Ok(value) => DiagnosticValue::Available(*value),
        Err(error) => DiagnosticValue::Unavailable(error.to_string()),
    };
    let limit = (raw & 0xffff) | (((raw >> 48) & 0xf) << 16);
    let granularity = raw & (1 << 55) != 0;
    let limit = if granularity {
        (limit << 12) | 0xfff
    } else {
        limit
    };
    let mut descriptor_base =
        ((raw >> 16) & 0xffff) | (((raw >> 32) & 0xff) << 16) | (((raw >> 56) & 0xff) << 24);
    if let Ok(Some(high)) = high_raw.as_ref() {
        descriptor_base |= (*high & 0xffff_ffff) << 32;
    }
    let base_value = if let Err(error) = &high_raw {
        if is_system_descriptor(raw) {
            DiagnosticValue::Unavailable(error.to_string())
        } else {
            DiagnosticValue::Available(VirtAddr(descriptor_base))
        }
    } else {
        DiagnosticValue::Available(VirtAddr(descriptor_base))
    };
    let present = raw & (1 << 47) != 0;
    let dpl = ((raw >> 45) & 0x3) as u8;
    let system = raw & (1 << 44) == 0;
    let type_code = ((raw >> 40) & 0xf) as u8;
    let long_mode = raw & (1 << 53) != 0;
    let default_size = raw & (1 << 54) != 0;
    GdtEntryDetail {
        index: index as u64,
        raw: DiagnosticValue::Available(raw),
        high_raw: high_value,
        base: base_value,
        limit: DiagnosticValue::Available(limit),
        type_code: DiagnosticValue::Available(type_code),
        descriptor_kind: DiagnosticValue::Available(if system {
            "system".to_string()
        } else {
            "code/data".to_string()
        }),
        dpl: DiagnosticValue::Available(dpl),
        present: DiagnosticValue::Available(present),
        long_mode: DiagnosticValue::Available(long_mode),
        default_size: DiagnosticValue::Available(default_size),
        granularity: DiagnosticValue::Available(granularity),
    }
}

fn decode_gdt(target: &Target, processor: u16, descriptor: DescriptorDetail) -> GdtDetail {
    let raw_count = descriptor.limit.saturating_add(8) / 8;
    let count = usize::try_from(raw_count).unwrap_or(MAX_GDT_ENTRIES + 1);
    let truncated = count > MAX_GDT_ENTRIES;
    let entry_count = count.clamp(1, MAX_GDT_ENTRIES);
    let memory = match kernel(target) {
        Ok(kernel) => kernel.memory(),
        Err(error) => {
            return GdtDetail {
                processor,
                base: descriptor.base,
                limit: descriptor.limit,
                entry_count: raw_count,
                truncated,
                entries: (0..entry_count)
                    .map(|index| unavailable_gdt_entry(index, error.to_string()))
                    .collect(),
            };
        }
    };
    let mut entries = Vec::with_capacity(entry_count);
    let mut index = 0usize;
    while index < entry_count {
        let address = VirtAddr(descriptor.base.0.wrapping_add((index * 8) as u64));
        let mut bytes = [0u8; 8];
        let raw = match memory.read_bytes(address, &mut bytes) {
            Ok(()) => u64::from_le_bytes(bytes),
            Err(error) => {
                entries.push(unavailable_gdt_entry(index, error.to_string()));
                index += 1;
                continue;
            }
        };
        let high = if is_system_descriptor(raw) && index + 1 < entry_count {
            let next_address = VirtAddr(descriptor.base.0.wrapping_add(((index + 1) * 8) as u64));
            let mut next_bytes = [0u8; 8];
            match memory.read_bytes(next_address, &mut next_bytes) {
                Ok(()) => Ok(Some(u64::from_le_bytes(next_bytes))),
                Err(error) => Err(error),
            }
        } else {
            Ok(None)
        };
        entries.push(decode_gdt_entry(index, raw, high));
        if is_system_descriptor(raw) && index + 1 < entry_count {
            index += 2;
        } else {
            index += 1;
        }
    }
    GdtDetail {
        processor,
        base: descriptor.base,
        limit: descriptor.limit,
        entry_count: raw_count,
        truncated,
        entries,
    }
}

impl Session {
    fn current_processor_for_cpu(&self) -> u16 {
        processor_index_from_backend_thread_id(&self.current_thread).unwrap_or(0)
    }

    fn backend_descriptor(&mut self, name: &str) -> Result<DescriptorDetail> {
        let names = self.register_map.names();
        if !names
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(name))
        {
            return Err(Error::FieldNotFound(name.to_string()));
        }
        let registers = self.read_registers()?;
        let base = self.register_map.read_u64(name, &registers)?;
        let limit_name = format!("{name}_limit");
        let limit = self
            .register_map
            .read_u64(&limit_name, &registers)
            .unwrap_or(0);
        Ok(DescriptorDetail {
            base: VirtAddr(base),
            limit,
        })
    }

    fn descriptor_for_cpu(
        &mut self,
        processor: u16,
        names: &[&str],
        direct_base_names: &[&str],
        direct_limit_names: &[&str],
        backend_name: &str,
    ) -> Result<DescriptorDetail> {
        if processor != self.current_processor_for_cpu() {
            return Err(Error::DebugInfo(
                "IDTR/GDTR ProcessorState is valid only for the halting processor".into(),
            ));
        }
        let location = cpu_location(&self.target, processor)?;
        let target_result = descriptor_from_target(
            &self.target,
            &location,
            names,
            direct_base_names,
            direct_limit_names,
        );
        match target_result {
            Ok(descriptor) => Ok(descriptor),
            Err(error) => self.backend_descriptor(backend_name).or(Err(error)),
        }
    }

    /// Decode KPCR/KPRCB essentials, using halted backend descriptor registers
    /// only when target-memory descriptor fields are unavailable; all other
    /// diagnostic values retain their target-memory layout/read errors.
    pub fn inspect_pcr(&mut self, processor: u16) -> Result<PcrDetail> {
        let mut detail = self.target.inspect_pcr(processor)?;
        let idtr = self.descriptor_for_cpu(
            processor,
            &["Idtr", "IDTR"],
            &["IdtBase", "IDTBase"],
            &["IdtLimit", "IDTLimit"],
            "idtr",
        );
        detail.idtr = DiagnosticValue::from_result(idtr);
        let gdtr = self.descriptor_for_cpu(
            processor,
            &["Gdtr", "GDTR"],
            &["GdtBase", "GDTBase"],
            &["GdtLimit", "GDTLimit"],
            "gdtr",
        );
        detail.gdtr = DiagnosticValue::from_result(gdtr);
        Ok(detail)
    }

    /// Decode one IDT vector or all 256 vectors from the halted processor's
    /// IDTR, falling back to backend register reads when PDB state is absent;
    /// each entry field preserves its own memory/symbol diagnostic.
    pub fn inspect_idt(&mut self, processor: u16, vector: Option<u16>) -> Result<IdtDetail> {
        if self.target.arch() == Arch::Arm64 {
            return Err(Error::DebugInfo(
                "!idt is not defined on ARM64 targets".into(),
            ));
        }
        validate_idt_vector(vector)?;
        let descriptor = self.descriptor_for_cpu(
            processor,
            &["Idtr", "IDTR"],
            &["IdtBase", "IDTBase"],
            &["IdtLimit", "IDTLimit"],
            "idtr",
        )?;
        Ok(decode_idt(&self.target, processor, descriptor, vector))
    }

    /// Decode the halted processor's bounded GDT, falling back to backend GDTR
    /// registers when PDB state is absent; each entry field preserves its own
    /// raw/descriptor diagnostic.
    pub fn inspect_gdt(&mut self, processor: u16) -> Result<GdtDetail> {
        if self.target.arch() == Arch::Arm64 {
            return Err(Error::DebugInfo(
                "!gdt is not defined on ARM64 targets".into(),
            ));
        }
        let descriptor = self.descriptor_for_cpu(
            processor,
            &["Gdtr", "GDTR"],
            &["GdtBase", "GDTBase"],
            &["GdtLimit", "GDTLimit"],
            "gdtr",
        )?;
        Ok(decode_gdt(&self.target, processor, descriptor))
    }

    /// Read one MSR on a halted processor after enforcing the backend MSR
    /// capability. The backend error is returned unchanged to the caller.
    pub fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        if self.backend.is_running() {
            return Err(Error::TargetRunning);
        }
        if !self
            .backend
            .capabilities()
            .iter()
            .any(|capability| capability.capability == DebugCapability::Msr && capability.supported)
        {
            return Err(Error::NotSupported);
        }
        self.backend.read_msr(processor, msr)
    }

    /// Write one MSR on a halted processor after enforcing the backend MSR
    /// capability. The backend error is returned unchanged to the caller.
    pub fn write_msr(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        if self.backend.is_running() {
            return Err(Error::TargetRunning);
        }
        if !self
            .backend
            .capabilities()
            .iter()
            .any(|capability| capability.capability == DebugCapability::Msr && capability.supported)
        {
            return Err(Error::NotSupported);
        }
        self.backend.write_msr(processor, msr, value)
    }
}

#[cfg(test)]
mod tests {
    use super::{msr_name, parse_msr_name};

    #[test]
    fn msr_name_aliases_round_trip() {
        for (name, value, canonical) in [
            ("TSC", 0x10, "TSC"),
            ("IA32_EFER", 0xc000_0080, "IA32_EFER"),
            ("MSR_IA32_LSTAR", 0xc000_0082, "IA32_LSTAR"),
            ("msr-ia32-gs-base", 0xc000_0101, "IA32_GS_BASE"),
        ] {
            assert_eq!(parse_msr_name(name), Some(value));
            assert_eq!(msr_name(value), Some(canonical));
        }
        assert_eq!(parse_msr_name("0x10"), None);
    }
}
