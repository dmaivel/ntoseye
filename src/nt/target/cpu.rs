//! cpu: structured inspector data (shared by the REPL, Python SDK, and MCP).

use std::sync::Arc;

use crate::arch::{Arch, Family};
use crate::base::bytes::before_nul;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::VirtAddr;
use crate::nt::cpu_state;
use crate::nt::guest::Image;
use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::nt::target::{DiagnosticValue, Target};
use ntoseye_macros::record;

const MAX_FIELD_BYTES: usize = 0x1000;
const IDT_VECTOR_COUNT: u16 = 256;
const MAX_GDT_ENTRIES: usize = 256;

/// A processor by number (`!pcr 1`), which the session checks against the
/// processor count. A command whose processor is omitted reads the one the
/// current vCPU is; a `Cpu` binds its own.
#[derive(Clone, Copy, Debug)]
pub struct Processor(pub u16);

/// An x86 descriptor table whose register a processor's `_KPRCB` saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorTable {
    Idt,
    Gdt,
}

impl DescriptorTable {
    /// The table register's name in a backend's register map.
    pub fn register(self) -> &'static str {
        match self {
            Self::Idt => "idtr",
            Self::Gdt => "gdtr",
        }
    }

    /// The `_KSPECIAL_REGISTERS` field holding the register.
    fn special_register_names(self) -> &'static [&'static str] {
        match self {
            Self::Idt => &["Idtr", "IDTR"],
            Self::Gdt => &["Gdtr", "GDTR"],
        }
    }

    /// The `_KPCR` fields holding the table's base and limit.
    fn kpcr_names(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Self::Idt => (&["IdtBase", "IDTBase"], &["IdtLimit", "IDTLimit"]),
            Self::Gdt => (&["GdtBase", "GDTBase"], &["GdtLimit", "GDTLimit"]),
        }
    }
}

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
    /// For a handler in `KiIsrThunk`, which dispatches through the
    /// processor's `_KPRCB.InterruptObject` table, the `_KINTERRUPT`
    /// connected to the vector and its service routine. None for other
    /// handlers and for a vector nothing is connected to.
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

/// Common AArch64 system registers, by the number Windows KD reads them
/// with (`rdmsr` on an ARM64 target): op0 << 16 | op1 << 12 | CRn << 8 |
/// CRm << 4 | op2.
const ARM64_SYSTEM_REGISTERS: &[(u32, &str)] = &[
    (0x3_0000, "MIDR_EL1"),
    (0x3_0005, "MPIDR_EL1"),
    (0x3_0006, "REVIDR_EL1"),
    (0x3_0040, "ID_AA64PFR0_EL1"),
    (0x3_0050, "ID_AA64DFR0_EL1"),
    (0x3_0060, "ID_AA64ISAR0_EL1"),
    (0x3_0061, "ID_AA64ISAR1_EL1"),
    (0x3_0070, "ID_AA64MMFR0_EL1"),
    (0x3_0071, "ID_AA64MMFR1_EL1"),
    (0x3_0100, "SCTLR_EL1"),
    (0x3_0102, "CPACR_EL1"),
    (0x3_0200, "TTBR0_EL1"),
    (0x3_0201, "TTBR1_EL1"),
    (0x3_0202, "TCR_EL1"),
    (0x3_0520, "ESR_EL1"),
    (0x3_0600, "FAR_EL1"),
    (0x3_0740, "PAR_EL1"),
    (0x3_0a20, "MAIR_EL1"),
    (0x3_0c00, "VBAR_EL1"),
    (0x3_0d01, "CONTEXTIDR_EL1"),
    (0x3_0d04, "TPIDR_EL1"),
    (0x3_0e10, "CNTKCTL_EL1"),
    (0x3_3001, "CTR_EL0"),
    (0x3_3007, "DCZID_EL0"),
    (0x3_3d02, "TPIDR_EL0"),
    (0x3_3d03, "TPIDRRO_EL0"),
    (0x3_3e00, "CNTFRQ_EL0"),
    (0x3_3e01, "CNTPCT_EL0"),
    (0x3_3e02, "CNTVCT_EL0"),
    (0x3_3e31, "CNTV_CTL_EL0"),
    (0x3_3e32, "CNTV_CVAL_EL0"),
];

fn named_registers(arch: Arch) -> &'static [(u32, &'static str)] {
    match arch {
        Arch::Amd64 => MSRS,
        Arch::Arm64 => ARM64_SYSTEM_REGISTERS,
    }
}

/// What `rdmsr` reads on `arch`: an `MSR`, or an ARM64 `system register`.
pub fn msr_kind(arch: Arch) -> &'static str {
    match arch {
        Arch::Amd64 => "MSR",
        Arch::Arm64 => "system register",
    }
}

/// The conventional name of register `msr` on `arch`.
pub fn msr_name(arch: Arch, msr: u32) -> Option<&'static str> {
    named_registers(arch)
        .iter()
        .find_map(|(value, name)| (*value == msr).then_some(*name))
}

/// A register's number from its name on `arch`: a conventional
/// `IA32_*`/`MSR_IA32_*` (or short `TSC`) MSR name on AMD64; on ARM64 a
/// system register's (`MIDR_EL1`), or its generic spelling
/// `S<op0>_<op1>_C<n>_C<m>_<op2>` (`S3_0_C0_C0_0`). Numeric expressions are
/// left to the REPL.
pub fn parse_msr_name(arch: Arch, name: &str) -> Option<u32> {
    let normalized = name.trim().to_ascii_uppercase().replace('-', "_");
    match arch {
        Arch::Amd64 => {
            let normalized = normalized.strip_prefix("MSR_").unwrap_or(&normalized);
            let normalized = normalized.strip_prefix("IA32_").unwrap_or(normalized);
            MSRS.iter()
                .find(|(_, candidate)| {
                    normalized == candidate.strip_prefix("IA32_").unwrap_or(candidate)
                })
                .map(|(value, _)| *value)
        }
        Arch::Arm64 => ARM64_SYSTEM_REGISTERS
            .iter()
            .find(|(_, candidate)| normalized == *candidate)
            .map(|(value, _)| *value)
            .or_else(|| generic_system_register(&normalized)),
    }
}

/// `S<op0>_<op1>_C<n>_C<m>_<op2>`, upper case, as the number KD reads the
/// register by.
fn generic_system_register(name: &str) -> Option<u32> {
    let mut parts = name.strip_prefix('S')?.split('_');
    let mut field = |prefix: &str, max: u32| {
        let value: u32 = parts.next()?.strip_prefix(prefix)?.parse().ok()?;
        (value <= max).then_some(value)
    };
    let op0 = field("", 3)?;
    let op1 = field("", 7)?;
    let crn = field("C", 15)?;
    let crm = field("C", 15)?;
    let op2 = field("", 7)?;
    if parts.next().is_some() {
        return None;
    }
    Some(op0 << 16 | op1 << 12 | crn << 8 | crm << 4 | op2)
}

fn kernel(target: &Target) -> Result<&Image> {
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
    Ok(String::from_utf8_lossy(before_nul(&bytes))
        .trim()
        .to_string())
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
        let pointer = kernel(target)?
            .types()
            .struct_with_layout(Arc::clone(parent), base)
            .read_pointer(name)?;
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

/// A processor's `_KPCR` and `_KPRCB`.
#[derive(Clone, Debug)]
pub struct CpuLocation {
    processor: u16,
    kpcr: DiagnosticValue<VirtAddr>,
    kprcb: VirtAddr,
}

/// Find `processor`'s control blocks; it fails only without its `_KPRCB`.
pub fn cpu_location(target: &Target, processor: u16) -> Result<CpuLocation> {
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
) -> Result<DescriptorRegister> {
    let layout = layout(target, type_name)?;
    Ok(DescriptorRegister {
        base: VirtAddr(field_u64(target, &layout, base, base_names)?),
        limit: field_u64(target, &layout, base, limit_names)?,
    })
}

fn descriptor_from_prcb(
    target: &Target,
    prcb: VirtAddr,
    names: &[&str],
) -> Result<DescriptorRegister> {
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
        Ok((descriptor_layout, descriptor_base)) => Ok(DescriptorRegister {
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
                Ok(DescriptorRegister {
                    base: VirtAddr(le_uint(&bytes[8..16])),
                    limit: le_uint(&bytes[6..8]),
                })
            } else if bytes.len() >= 10 {
                Ok(DescriptorRegister {
                    base: VirtAddr(le_uint(&bytes[2..10])),
                    limit: le_uint(&bytes[0..2]),
                })
            } else {
                Err(nested_error)
            }
        }
    }
}

/// `table`'s register as Windows saved it for the processor at `location`:
/// its `_KPRCB`'s `ProcessorState`, else the `_KPCR`'s base and limit.
pub fn descriptor_from_target(
    target: &Target,
    location: &CpuLocation,
    table: DescriptorTable,
) -> Result<DescriptorRegister> {
    descriptor_from_prcb(target, location.kprcb, table.special_register_names()).or_else(|_| {
        let kpcr = match &location.kpcr {
            DiagnosticValue::Available(kpcr) => *kpcr,
            DiagnosticValue::Unavailable(error) => {
                return Err(Error::DebugInfo(error.clone()));
            }
        };
        let (base_names, limit_names) = table.kpcr_names();
        descriptor_from_layout(target, "_KPCR", kpcr, base_names, limit_names)
    })
}

/// Refuse an IDT vector past the table's 256 entries.
pub fn validate_idt_vector(vector: Option<u16>) -> Result<()> {
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
    pub fn inspect_pcr(&self, processor: u16) -> Result<Pcr> {
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
                DiagnosticValue::unavailable(error.clone()),
                DiagnosticValue::unavailable(error.clone()),
                DiagnosticValue::unavailable(error.clone()),
                DiagnosticValue::unavailable(error),
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
                DiagnosticValue::unavailable(error.clone()),
                DiagnosticValue::unavailable(error.clone()),
                DiagnosticValue::unavailable(error),
            )
        });
        Ok(Pcr {
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
            idtr: DiagnosticValue::from_result(descriptor_from_target(
                self,
                &location,
                DescriptorTable::Idt,
            )),
            gdtr: DiagnosticValue::from_result(descriptor_from_target(
                self,
                &location,
                DescriptorTable::Gdt,
            )),
            tss_base: tss_base(self, &location),
        })
    }

    /// Decode selected `_KPRCB` fields and nested ProcessorState metadata.
    /// Every scalar read is retained as a `DiagnosticValue` so partial PDBs do
    /// not make unrelated processor counters disappear.
    pub fn inspect_prcb(&self, processor: u16) -> Result<Prcb> {
        let location = cpu_location(self, processor)?;
        let prcb_layout = layout(self, "_KPRCB")?;
        let processor_state = DiagnosticValue::from_result(
            nested_field(
                self,
                &prcb_layout,
                location.kprcb,
                &["ProcessorState"],
                "_KPROCESSOR_STATE",
            )
            .map(|(state_layout, state_base)| {
                let special_registers = DiagnosticValue::from_result(
                    nested_field(
                        self,
                        &state_layout,
                        state_base,
                        &["SpecialRegisters"],
                        "_KSPECIAL_REGISTERS",
                    )
                    .map(|(special_layout, special_base)| {
                        SpecialRegistersArea {
                            address: special_base,
                            size: special_layout.size as u64,
                            name: special_layout.name.clone(),
                        }
                    }),
                );
                ProcessorStateArea {
                    address: state_base,
                    size: state_layout.size as u64,
                    name: state_layout.name.clone(),
                    context_frame: DiagnosticValue::from_result(
                        state_layout
                            .field_offset("ContextFrame")
                            .map(|offset| state_base + offset),
                    ),
                    special_registers,
                }
            }),
        );
        Ok(Prcb {
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
    pub fn inspect_irql(&self, processor: u16) -> Result<Irql> {
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
                DiagnosticValue::Available(self.arch().irql_name(*value).to_string())
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
        };
        Ok(Irql {
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
    pub fn inspect_idt(&self, processor: u16, vector: Option<u16>) -> Result<Idt> {
        // Only an x86-family processor dispatches interrupts through an IDT.
        if self.arch().family() != Family::X86 {
            return Err(Error::DebugInfo(format!(
                "!idt is not defined on {} targets",
                self.arch().label()
            )));
        }
        validate_idt_vector(vector)?;
        let location = cpu_location(self, processor)?;
        let descriptor = descriptor_from_target(self, &location, DescriptorTable::Idt)?;
        Ok(decode_idt(self, location.processor, descriptor, vector))
    }

    /// Decode vendor, family/model/stepping, speed, and `_KPRCB` feature
    /// fields. Each PDB/memory read is independent; triage PRCB metadata is
    /// used as a complete fallback when the processor block cannot be found.
    pub fn inspect_cpuinfo(&self, processor: u16) -> Result<CpuInfo> {
        let location = match cpu_location(self, processor) {
            Ok(location) => location,
            Err(error) => {
                if let Some(info) = self
                    .phys
                    .dmp_info()
                    .and_then(|dump| dump.triage_prcb_info.as_ref())
                {
                    let unavailable_addr =
                        |message: &str| DiagnosticValue::unavailable(message.to_string());
                    let unavailable_num =
                        |message: &str| DiagnosticValue::unavailable(message.to_string());
                    return Ok(CpuInfo {
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
                    DiagnosticValue::unavailable(error.clone()),
                    DiagnosticValue::unavailable(error),
                )
            }
        };
        // An ARM64 processor names itself in MIDR_EL1, which its PRCB does
        // not copy: the x86 fields are not missing there, but not kept.
        let (vendor, family, model, stepping) = if self.arch() == Arch::Arm64 {
            let reason = "an ARM64 PRCB keeps none; MIDR_EL1 identifies the processor \
                          (rdmsr MIDR_EL1 on a live target)";
            let kept = |value: DiagnosticValue<u64>| match value {
                DiagnosticValue::Unavailable(_) => DiagnosticValue::unavailable(reason.to_string()),
                value => value,
            };
            let vendor = match vendor {
                DiagnosticValue::Unavailable(_) => DiagnosticValue::unavailable(reason.to_string()),
                vendor => vendor,
            };
            (vendor, kept(family), kept(model), kept(stepping))
        } else {
            (vendor, family, model, stepping)
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
                .map(|info| CpuTriageFallback {
                    processor_number: info.processor_number,
                    vendor: info.vendor_string.clone(),
                    family: info.cpu_type,
                    mhz: info.mhz,
                })
        } else {
            None
        };
        Ok(CpuInfo {
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

fn is_nt_module(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("ntoskrnl") || name.contains("ntkrnl") || name == "nt"
}

/// The `_KINTERRUPT` connected to `vector`, for a `handler` in `KiIsrThunk`,
/// which dispatches through `objects` (the processor's
/// `_KPRCB.InterruptObject` table): its address and service routine. None
/// for another handler, and for a vector nothing is connected to.
fn connected_interrupt(
    target: &Target,
    objects: Option<VirtAddr>,
    handler: u64,
    vector: u16,
) -> Option<String> {
    let thunk = target
        .symbols
        .find_symbol_with_module(target.kernel_dtb(), "nt!KiIsrThunk")
        .ok()
        .flatten()
        .map(|(address, _)| address.0)?;
    if handler < thunk || handler - thunk >= 0x1000 {
        return None;
    }
    let memory = kernel(target).ok()?.memory();
    let Some(objects) = objects else {
        return Some("KiIsrThunk: the processor's interrupt object table is not known".into());
    };
    let interrupt = memory
        .read_pointer(objects + u64::from(vector) * 8)
        .ok()
        .filter(|interrupt| !interrupt.is_zero())?;
    // A message-signalled interrupt's ServiceRoutine is the kernel's
    // KiInterruptMessageDispatch; the driver's is MessageServiceRoutine.
    let interrupt_layout = layout(target, "_KINTERRUPT").ok();
    let routine_in = |field: &str| {
        let offset = interrupt_layout.as_ref()?.field_offset(field).ok()?;
        memory
            .read_pointer(interrupt + offset)
            .ok()
            .filter(|routine| !routine.is_zero())
    };
    let routine = routine_in("MessageServiceRoutine")
        .or_else(|| routine_in("ServiceRoutine"))
        .map(|routine| {
            target
                .symbols
                .format_closest_symbol_for_address(target.kernel_dtb(), routine)
                .unwrap_or_else(|| format!("{:#x}", routine.0))
        })
        .unwrap_or_else(|| "-".into());
    Some(format!("KINTERRUPT {:#x}  {routine}", interrupt.0))
}

/// Where `processor`'s `_KPRCB.InterruptObject` table is.
fn interrupt_objects(target: &Target, processor: u16) -> Option<VirtAddr> {
    let prcb = cpu_state::kprcb_for_processor(target, processor).ok()?;
    let offset = layout(target, "_KPRCB")
        .ok()?
        .field_offset("InterruptObject")
        .ok()?;
    Some(prcb + offset)
}

fn unavailable_idt_entry(vector: u16, address: VirtAddr, error: String) -> IdtGate {
    IdtGate {
        vector,
        address,
        handler: DiagnosticValue::unavailable(error.clone()),
        symbol: DiagnosticValue::unavailable(error.clone()),
        selector: DiagnosticValue::unavailable(error.clone()),
        ist: DiagnosticValue::unavailable(error.clone()),
        gate_type: DiagnosticValue::unavailable(error.clone()),
        gate_name: DiagnosticValue::unavailable(error.clone()),
        dpl: DiagnosticValue::unavailable(error.clone()),
        present: DiagnosticValue::unavailable(error.clone()),
        non_nt_hook: DiagnosticValue::unavailable(error.clone()),
        ki_isr_thunk: DiagnosticValue::unavailable(error),
    }
}

fn decode_idt_entry(target: &Target, base: u64, vector: u16, objects: Option<VirtAddr>) -> IdtGate {
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
        return IdtGate {
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
            ki_isr_thunk: DiagnosticValue::Available(connected_interrupt(
                target, objects, offset, vector,
            )),
        };
    };
    unavailable_idt_entry(vector, address, error.to_string())
}

/// Decode `vector`, or all 256 vectors, of the IDT `descriptor` names.
pub fn decode_idt(
    target: &Target,
    processor: u16,
    descriptor: DescriptorRegister,
    vector: Option<u16>,
) -> Idt {
    let vectors: Vec<u16> = vector
        .map(|vector| vec![vector])
        .unwrap_or_else(|| (0..IDT_VECTOR_COUNT).collect());
    let objects = interrupt_objects(target, processor);
    let entries = vectors
        .into_iter()
        .map(|vector| decode_idt_entry(target, descriptor.base.0, vector, objects))
        .collect();
    let descriptor_entries = descriptor.limit.saturating_add(1) / 16;
    let truncated = match vector {
        Some(vector) => u64::from(vector) >= descriptor_entries,
        None => descriptor.limit < (u64::from(IDT_VECTOR_COUNT) * 16 - 1),
    };
    Idt {
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

fn unavailable_gdt_entry(index: usize, error: String) -> GdtDescriptor {
    GdtDescriptor {
        index: index as u64,
        raw: DiagnosticValue::unavailable(error.clone()),
        high_raw: DiagnosticValue::unavailable(error.clone()),
        base: DiagnosticValue::unavailable(error.clone()),
        limit: DiagnosticValue::unavailable(error.clone()),
        type_code: DiagnosticValue::unavailable(error.clone()),
        descriptor_kind: DiagnosticValue::unavailable(error.clone()),
        dpl: DiagnosticValue::unavailable(error.clone()),
        present: DiagnosticValue::unavailable(error.clone()),
        long_mode: DiagnosticValue::unavailable(error.clone()),
        default_size: DiagnosticValue::unavailable(error.clone()),
        granularity: DiagnosticValue::unavailable(error),
    }
}

fn decode_gdt_entry(index: usize, raw: u64, high_raw: Result<Option<u64>>) -> GdtDescriptor {
    let high_value = match high_raw.as_ref() {
        Ok(value) => DiagnosticValue::Available(*value),
        Err(error) => DiagnosticValue::unavailable(error.to_string()),
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
            DiagnosticValue::unavailable(error.to_string())
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
    GdtDescriptor {
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

/// Decode the GDT `descriptor` names, bounded to 256 entries.
pub fn decode_gdt(target: &Target, processor: u16, descriptor: DescriptorRegister) -> Gdt {
    let raw_count = descriptor.limit.saturating_add(8) / 8;
    let count = usize::try_from(raw_count).unwrap_or(MAX_GDT_ENTRIES + 1);
    let truncated = count > MAX_GDT_ENTRIES;
    let entry_count = count.clamp(1, MAX_GDT_ENTRIES);
    let memory = match kernel(target) {
        Ok(kernel) => kernel.memory(),
        Err(error) => {
            return Gdt {
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
    Gdt {
        processor,
        base: descriptor.base,
        limit: descriptor.limit,
        entry_count: raw_count,
        truncated,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::{msr_name, parse_msr_name};
    use crate::arch::Arch;
    use crate::backend::kd::registers::{ARM64_WINDBG_ESR_EL1, ARM64_WINDBG_TTBR1_EL1};

    #[test]
    fn msr_name_aliases_round_trip() {
        for (name, value, canonical) in [
            ("TSC", 0x10, "TSC"),
            ("IA32_EFER", 0xc000_0080, "IA32_EFER"),
            ("MSR_IA32_LSTAR", 0xc000_0082, "IA32_LSTAR"),
            ("msr-ia32-gs-base", 0xc000_0101, "IA32_GS_BASE"),
        ] {
            assert_eq!(parse_msr_name(Arch::Amd64, name), Some(value));
            assert_eq!(msr_name(Arch::Amd64, value), Some(canonical));
        }
        assert_eq!(parse_msr_name(Arch::Amd64, "0x10"), None);
    }

    /// An ARM64 target's registers are its system registers, by name or
    /// generic spelling, in the encoding KD reads them by; x86 names mean
    /// nothing there.
    #[test]
    fn arm64_names_are_system_registers() {
        assert_eq!(
            parse_msr_name(Arch::Arm64, "ttbr1_el1"),
            Some(ARM64_WINDBG_TTBR1_EL1)
        );
        assert_eq!(
            parse_msr_name(Arch::Arm64, "S3_0_C5_C2_0"),
            Some(ARM64_WINDBG_ESR_EL1)
        );
        assert_eq!(msr_name(Arch::Arm64, ARM64_WINDBG_ESR_EL1), Some("ESR_EL1"));
        assert_eq!(parse_msr_name(Arch::Arm64, "TSC"), None);
        assert_eq!(parse_msr_name(Arch::Arm64, "S3_0_C16_C0_0"), None);
        assert_eq!(msr_name(Arch::Arm64, 0x10), None);
    }
}
