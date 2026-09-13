use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::cpu_state;
use crate::dbg_backend::DebugCapability;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::WinObject;
use crate::session::processor_index_from_backend_thread_id;
use crate::symbols::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::target::Target;
use crate::triage::TriagePrcbInfo;
use crate::types::{Arch, VirtAddr};
use crate::ui;

use crate::repl::*;

const MAX_FIELD_BYTES: usize = 0x1000;
const IDT_VECTOR_COUNT: u16 = 256;
const MAX_GDT_ENTRIES: usize = 256;
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

#[derive(Clone, Copy)]
struct CpuLocation {
    processor: u16,
    kpcr: Option<VirtAddr>,
    kprcb: VirtAddr,
}

#[derive(Clone, Copy, Debug)]
struct Descriptor {
    base: u64,
    limit: u64,
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

fn cpu_location(state: &mut ReplState<'_>, text: Option<&str>) -> Result<CpuLocation> {
    let processor = parse_processor(state, text)?;
    let kprcb = cpu_state::kprcb_for_processor(&state.ctx.target, processor)?;
    Ok(CpuLocation {
        processor,
        // A missing ARM64 `_KPCR.Prcb` field should not hide the KPRCB, which
        // is independently addressable through KiProcessorBlock.
        kpcr: cpu_state::kpcr_for_processor(&state.ctx.target, processor).ok(),
        kprcb,
    })
}

fn rendered_u64(value: Result<u64>) -> String {
    value
        .map(|value| ui::addr(value).to_string())
        .unwrap_or_else(|error| format!("<unavailable: {error}>"))
}

fn rendered_decimal(value: &Result<u64>) -> String {
    match value {
        Ok(value) => format!("{value} ({value:#x})"),
        Err(error) => format!("<unavailable: {error}>"),
    }
}

fn print_u64_field(
    target: &Target,
    layout: &Arc<TypeInfo>,
    base: VirtAddr,
    label: &str,
    names: &[&str],
) {
    outln!(
        "  {label:<20}: {}",
        rendered_u64(field_u64(target, layout, base, names))
    );
}

fn print_decimal_field(
    target: &Target,
    layout: &Arc<TypeInfo>,
    base: VirtAddr,
    label: &str,
    names: &[&str],
) {
    outln!(
        "  {label:<20}: {}",
        rendered_decimal(&field_u64(target, layout, base, names))
    );
}

fn descriptor_from_layout(
    target: &Target,
    type_name: &str,
    base: VirtAddr,
    base_names: &[&str],
    limit_names: &[&str],
) -> Result<Descriptor> {
    let layout = layout(target, type_name)?;
    Ok(Descriptor {
        base: field_u64(target, &layout, base, base_names)?,
        limit: field_u64(target, &layout, base, limit_names)?,
    })
}

fn descriptor_from_prcb(target: &Target, prcb: VirtAddr, names: &[&str]) -> Result<Descriptor> {
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
        Ok((descriptor_layout, descriptor_base)) => Ok(Descriptor {
            base: field_u64(
                target,
                &descriptor_layout,
                descriptor_base,
                &["Base", "Address"],
            )?,
            limit: field_u64(
                target,
                &descriptor_layout,
                descriptor_base,
                &["Limit", "Length"],
            )?,
        }),
        Err(nested_error) => {
            // Some public/skeletal PDBs describe KDESCRIPTOR as an opaque
            // aggregate. Its AMD64 wire layout is still stable: Limit at +6
            // and Base at +8. Keep this read bounded by the PDB field size.
            let bytes = match field_bytes(target, &special_registers, special_registers_base, names)
            {
                Ok(bytes) => bytes,
                Err(_) => return Err(nested_error),
            };
            if bytes.len() >= 16 {
                Ok(Descriptor {
                    base: le_uint(&bytes[8..16]),
                    limit: le_uint(&bytes[6..8]),
                })
            } else if bytes.len() >= 10 {
                Ok(Descriptor {
                    base: le_uint(&bytes[2..10]),
                    limit: le_uint(&bytes[0..2]),
                })
            } else {
                Err(nested_error)
            }
        }
    }
}

fn backend_descriptor(state: &mut ReplState<'_>, name: &str) -> Result<Descriptor> {
    let names = state.ctx.register_map.names();
    if !names
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return Err(Error::FieldNotFound(name.to_string()));
    }
    let registers = state.ctx.read_registers()?;
    let base = state.ctx.register_map.read_u64(name, &registers)?;
    let limit_name = format!("{name}_limit");
    let limit = state
        .ctx
        .register_map
        .read_u64(&limit_name, &registers)
        .unwrap_or(0);
    Ok(Descriptor { base, limit })
}

fn descriptor_for(
    state: &mut ReplState<'_>,
    location: CpuLocation,
    names: &[&str],
    direct_base_names: &[&str],
    direct_limit_names: &[&str],
    backend_name: &str,
) -> Result<Descriptor> {
    if location.processor != current_processor(state) {
        return Err(Error::DebugInfo(
            "IDTR/GDTR ProcessorState is valid only for the halting processor".into(),
        ));
    }
    let target_result = {
        let target = &state.ctx.target;
        descriptor_from_prcb(target, location.kprcb, names).or_else(|_| {
            let kpcr = location
                .kpcr
                .ok_or_else(|| Error::DebugInfo("_KPCR address unavailable".into()))?;
            descriptor_from_layout(target, "_KPCR", kpcr, direct_base_names, direct_limit_names)
        })
    };
    match target_result {
        Ok(descriptor) => Ok(descriptor),
        Err(error) => backend_descriptor(state, backend_name).or(Err(error)),
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
            // POWER_LEVEL is an AMD64 alias for IPI_LEVEL at 14; use the
            // canonical WinDbg spelling in output.
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

fn msr_name(msr: u32) -> Option<&'static str> {
    MSRS.iter()
        .find_map(|(value, name)| (*value == msr).then_some(*name))
}

fn parse_msr(state: &ReplState<'_>, text: &str) -> Result<u32> {
    let normalized = text.trim().to_ascii_uppercase().replace('-', "_");
    let normalized = normalized.strip_prefix("MSR_").unwrap_or(&normalized);
    let normalized = normalized.strip_prefix("IA32_").unwrap_or(normalized);
    if let Some((msr, _)) = MSRS
        .iter()
        .find(|(_, name)| normalized == name.strip_prefix("IA32_").unwrap_or(name))
    {
        return Ok(*msr);
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

fn command_capability(state: &ReplState<'_>, capability: DebugCapability) -> bool {
    let capabilities = state.ctx.backend.capabilities();
    if supports_capability(&capabilities, capability) {
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

fn print_triage_prcb(info: &TriagePrcbInfo) {
    outln!("CPU information from triage-dump PRCB metadata");
    outln!("  processor number    : {}", info.processor_number);
    outln!("  vendor              : {}", info.vendor_string);
    outln!(
        "  family              : {} ({:#x})",
        info.cpu_type,
        info.cpu_type
    );
    outln!("  model/stepping      : <unavailable>");
    outln!("  speed MHz           : {}", info.mhz);
    outln!("  feature bits        : <unavailable>");
}

impl ReplState<'_> {
    fn cmd_rdmsr(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !command_capability(self, DebugCapability::Msr) {
            return Ok(());
        }
        let (msr_text, processor_text) = match invocation.argv.as_slice() {
            [msr] => (msr.as_ref(), None),
            [switch, processor, msr] if switch.as_ref().eq_ignore_ascii_case("/p") => {
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

        match self.ctx.backend.read_msr(processor, msr) {
            Ok(value) => {
                let name = msr_name(msr).unwrap_or("MSR");
                outln!(
                    "processor {}  {} ({:#x}) = {}",
                    processor,
                    name,
                    msr,
                    render_msr_value(&self.ctx.target, value)
                );
            }
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
        let value = match Expr::eval_with_radix(
            require_arg!(invocation, 1, "wrmsr"),
            &self.ctx.target,
            self.radix,
        ) {
            Ok(value) => value.0,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let processor = current_processor(self);
        match self.ctx.backend.write_msr(processor, msr, value) {
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
        let location = match cpu_location(self, invocation.arg(0)) {
            Ok(location) => location,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let kpcr_layout = layout(&self.ctx.target, "_KPCR").ok();
        outln!(
            "KPCR for processor {} at {} (KPRCB {})",
            location.processor,
            location
                .kpcr
                .map(|address| ui::addr(address.0).to_string())
                .unwrap_or_else(|| "<unavailable>".to_string()),
            ui::addr(location.kprcb.0)
        );
        match (location.kpcr, kpcr_layout.as_ref()) {
            (Some(kpcr), Some(kpcr_layout)) => {
                print_u64_field(
                    &self.ctx.target,
                    kpcr_layout,
                    kpcr,
                    "KdVersionBlock",
                    &["KdVersionBlock"],
                );
                print_u64_field(
                    &self.ctx.target,
                    kpcr_layout,
                    kpcr,
                    "CurrentPrcb",
                    &["CurrentPrcb"],
                );
                print_decimal_field(
                    &self.ctx.target,
                    kpcr_layout,
                    kpcr,
                    "Irql",
                    &["Irql", "CurrentIrql"],
                );
                print_u64_field(
                    &self.ctx.target,
                    kpcr_layout,
                    kpcr,
                    "Self",
                    &["Self", "SelfPcr"],
                );
            }
            (None, _) => outln!("  KPCR fields         : <unavailable: KPCR address unavailable>"),
            (_, None) => outln!("  KPCR fields         : <unavailable: _KPCR layout unavailable>"),
        }

        match layout(&self.ctx.target, "_KPRCB") {
            Ok(prcb_layout) => {
                outln!("  KPRCB fields:");
                print_u64_field(
                    &self.ctx.target,
                    &prcb_layout,
                    location.kprcb,
                    "CurrentThread",
                    &["CurrentThread"],
                );
                print_u64_field(
                    &self.ctx.target,
                    &prcb_layout,
                    location.kprcb,
                    "NextThread",
                    &["NextThread"],
                );
                print_u64_field(
                    &self.ctx.target,
                    &prcb_layout,
                    location.kprcb,
                    "IdleThread",
                    &["IdleThread"],
                );
            }
            Err(error) => outln!("  KPRCB fields       : <unavailable: {error}>"),
        }

        for (label, names, direct_base, direct_limit, backend_name) in [
            (
                "IDTR",
                &["Idtr", "IDTR"][..],
                &["IdtBase", "IDTBase"][..],
                &["IdtLimit", "IDTLimit"][..],
                "idtr",
            ),
            (
                "GDTR",
                &["Gdtr", "GDTR"][..],
                &["GdtBase", "GDTBase"][..],
                &["GdtLimit", "GDTLimit"][..],
                "gdtr",
            ),
        ] {
            match descriptor_for(
                self,
                location,
                names,
                direct_base,
                direct_limit,
                backend_name,
            ) {
                Ok(descriptor) => outln!(
                    "  {label:<20}: base {} limit {:#x}",
                    ui::addr(descriptor.base),
                    descriptor.limit
                ),
                Err(error) => outln!("  {label:<20}: <unavailable: {error}>"),
            }
        }
        let tss = match (location.kpcr, kpcr_layout.as_ref()) {
            (Some(kpcr), Some(kpcr_layout)) => {
                field_u64(&self.ctx.target, kpcr_layout, kpcr, &["TssBase", "Tss"]).or_else(|_| {
                    layout(&self.ctx.target, "_KPRCB").and_then(|prcb_layout| {
                        field_u64(
                            &self.ctx.target,
                            &prcb_layout,
                            location.kprcb,
                            &["TssBase", "Tss"],
                        )
                    })
                })
            }
            _ => layout(&self.ctx.target, "_KPRCB").and_then(|prcb_layout| {
                field_u64(
                    &self.ctx.target,
                    &prcb_layout,
                    location.kprcb,
                    &["TssBase", "Tss"],
                )
            }),
        };
        outln!("  {:<20}: {}", "TssBase", rendered_u64(tss));
        Ok(())
    }

    fn cmd_prcb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let location = match cpu_location(self, invocation.arg(0)) {
            Ok(location) => location,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let prcb_layout = match layout(&self.ctx.target, "_KPRCB") {
            Ok(layout) => layout,
            Err(error) => {
                error!("cannot decode _KPRCB: {error}");
                return Ok(());
            }
        };
        outln!(
            "KPRCB for processor {} at {}",
            location.processor,
            ui::addr(location.kprcb.0)
        );
        print_decimal_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "Number",
            &["Number", "ProcessorNumber"],
        );
        print_u64_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "CurrentThread",
            &["CurrentThread"],
        );
        print_u64_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "NextThread",
            &["NextThread"],
        );
        print_u64_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "IdleThread",
            &["IdleThread"],
        );
        print_decimal_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "DpcRoutineActive",
            &["DpcRoutineActive"],
        );
        print_decimal_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            "InterruptCount",
            &["InterruptCount"],
        );
        match nested_field(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["ProcessorState"],
            "_KPROCESSOR_STATE",
        ) {
            Ok((processor_state, base)) => {
                outln!(
                    "  ProcessorState      : {} ({} bytes, {})",
                    ui::addr(base.0),
                    processor_state.size,
                    processor_state.name
                );
                print_u64_field(
                    &self.ctx.target,
                    &processor_state,
                    base,
                    "ContextFrame",
                    &["ContextFrame"],
                );
                match nested_field(
                    &self.ctx.target,
                    &processor_state,
                    base,
                    &["SpecialRegisters"],
                    "_KSPECIAL_REGISTERS",
                ) {
                    Ok((special, special_base)) => outln!(
                        "  SpecialRegisters    : {} ({} bytes, {})",
                        ui::addr(special_base.0),
                        special.size,
                        special.name
                    ),
                    Err(error) => outln!("  SpecialRegisters    : <unavailable: {error}>"),
                }
            }
            Err(error) => outln!("  ProcessorState      : <unavailable: {error}>"),
        }
        Ok(())
    }

    fn cmd_irql(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let location = match cpu_location(self, invocation.arg(0)) {
            Ok(location) => location,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let value = location
            .kpcr
            .and_then(|kpcr| {
                let kpcr_layout = layout(&self.ctx.target, "_KPCR").ok()?;
                field_u64(
                    &self.ctx.target,
                    &kpcr_layout,
                    kpcr,
                    &["Irql", "CurrentIrql"],
                )
                .ok()
            })
            .ok_or_else(|| Error::DebugInfo("_KPCR IRQL unavailable".into()))
            .or_else(|_| {
                let prcb_layout = layout(&self.ctx.target, "_KPRCB")?;
                field_u64(
                    &self.ctx.target,
                    &prcb_layout,
                    location.kprcb,
                    &["CurrentIrql", "Irql"],
                )
            });
        match value {
            Ok(value) => outln!(
                "processor {} IRQL {} ({})",
                location.processor,
                value,
                irql_name(self.ctx.target.arch(), value)
            ),
            Err(error) => error!("current IRQL unavailable: {error}"),
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
        let location = match cpu_location(self, None) {
            Ok(location) => location,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let descriptor = match descriptor_for(
            self,
            location,
            &["Idtr", "IDTR"],
            &["IdtBase", "IDTBase"],
            &["IdtLimit", "IDTLimit"],
            "idtr",
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                error!("IDTR unavailable: {error}");
                return Ok(());
            }
        };
        let vector = match invocation.arg(0) {
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(value) if value.0 < u64::from(IDT_VECTOR_COUNT) => Some(value.0 as u16),
                Ok(value) => {
                    error!("IDT vector {:#x} is outside 0..255", value.0);
                    return Ok(());
                }
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => None,
        };
        outln!(
            "IDT processor {} base {} limit {:#x}",
            location.processor,
            ui::addr(descriptor.base),
            descriptor.limit
        );
        if let Some(vector) = vector {
            print_idt_entry(&self.ctx.target, descriptor.base, vector);
        } else {
            for vector in 0..IDT_VECTOR_COUNT {
                print_idt_entry(&self.ctx.target, descriptor.base, vector);
            }
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
        let location = match cpu_location(self, None) {
            Ok(location) => location,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let descriptor = match descriptor_for(
            self,
            location,
            &["Gdtr", "GDTR"],
            &["GdtBase", "GDTBase"],
            &["GdtLimit", "GDTLimit"],
            "gdtr",
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                error!("GDTR unavailable: {error}");
                return Ok(());
            }
        };
        let entry_count =
            (((descriptor.limit.saturating_add(8)) / 8) as usize).clamp(1, MAX_GDT_ENTRIES);
        outln!(
            "GDT processor {} base {} limit {:#x} ({} entries)",
            location.processor,
            ui::addr(descriptor.base),
            descriptor.limit,
            entry_count
        );
        let memory = kernel(&self.ctx.target)?.memory();
        let mut index = 0;
        while index < entry_count {
            let address = VirtAddr(descriptor.base.wrapping_add((index * 8) as u64));
            let mut bytes = [0u8; 8];
            let raw = match memory.read_bytes(address, &mut bytes) {
                Ok(()) => u64::from_le_bytes(bytes),
                Err(error) => {
                    outln!("  {:>3}: <unavailable: {error}>", index);
                    index += 1;
                    continue;
                }
            };
            if is_system_descriptor(raw) && index + 1 < entry_count {
                let next_address = VirtAddr(descriptor.base.wrapping_add(((index + 1) * 8) as u64));
                let mut next_bytes = [0u8; 8];
                match memory.read_bytes(next_address, &mut next_bytes) {
                    Ok(()) => print_gdt_entry(index, raw, Some(u64::from_le_bytes(next_bytes))),
                    Err(error) => outln!("  {:>3}: <unavailable: {error}>", index),
                }
                index += 2;
            } else {
                print_gdt_entry(index, raw, None);
                index += 1;
            }
        }
        Ok(())
    }

    fn cmd_cpuinfo(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let location = match cpu_location(self, None) {
            Ok(location) => location,
            Err(error) => {
                if let Some(info) = self
                    .ctx
                    .target
                    .phys
                    .dmp_info()
                    .and_then(|dump| dump.triage_prcb_info.as_ref())
                {
                    print_triage_prcb(info);
                    return Ok(());
                }
                error!("{error}");
                return Ok(());
            }
        };
        let prcb_layout = match layout(&self.ctx.target, "_KPRCB") {
            Ok(layout) => layout,
            Err(error) => {
                error!("cannot decode _KPRCB: {error}");
                return Ok(());
            }
        };
        let vendor_string = field_string(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["VendorString", "Vendor"],
        );
        let cpu_vendor = field_u64(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["CpuVendor", "VendorId"],
        );
        let cpu_type = field_u64(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["CpuType", "CpuFamily", "Family"],
        );
        let cpu_step = field_u64(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["CpuStep", "Stepping", "CpuStepping"],
        );
        let mhz = field_u64(
            &self.ctx.target,
            &prcb_layout,
            location.kprcb,
            &["MHz", "Mhz", "CurrentMHz"],
        );
        outln!(
            "CPU information for processor {} (KPRCB {})",
            location.processor,
            ui::addr(location.kprcb.0)
        );
        outln!(
            "  vendor              : {}",
            match &vendor_string {
                Ok(value) => value.clone(),
                Err(error) => format!("<unavailable: {error}>"),
            }
        );
        outln!("  vendor id           : {}", rendered_decimal(&cpu_vendor));
        outln!("  family              : {}", rendered_decimal(&cpu_type));
        match &cpu_step {
            Ok(value) => outln!(
                "  model/stepping      : model {:#x} stepping {}",
                (*value >> 8) & 0xff,
                *value & 0xff
            ),
            Err(error) => outln!("  model/stepping      : <unavailable: {error}>"),
        }
        outln!("  speed MHz           : {}", rendered_decimal(&mhz));
        let mut feature_found = false;
        for names in [
            &["FeatureBits"][..],
            &["FeatureBitsEx"][..],
            &["ProcessorFeatures"][..],
            &["XStateFeatures"][..],
        ] {
            if let Ok(value) = field_u64(&self.ctx.target, &prcb_layout, location.kprcb, names) {
                feature_found = true;
                outln!("  {:<19}: {}", names[0], ui::addr(value));
            }
        }
        if !feature_found {
            outln!("  feature bits        : <unavailable>");
        }

        if vendor_string.is_err()
            && cpu_vendor.is_err()
            && cpu_type.is_err()
            && cpu_step.is_err()
            && mhz.is_err()
            && let Some(info) = self
                .ctx
                .target
                .phys
                .dmp_info()
                .and_then(|dump| dump.triage_prcb_info.as_ref())
        {
            print_triage_prcb(info);
        }
        Ok(())
    }
}

fn print_idt_entry(target: &Target, base: u64, vector: u16) {
    let address = VirtAddr(base.wrapping_add(u64::from(vector) * 16));
    let mut bytes = [0u8; 16];
    if let Err(error) = kernel(target).and_then(|nt| nt.memory().read_bytes(address, &mut bytes)) {
        outln!("  {:02x}: <unavailable: {error}>", vector);
        return;
    }
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
        .format_closest_symbol_for_address(target.kernel_dtb(), VirtAddr(offset))
        .unwrap_or_else(|| ui::addr(offset).to_string());
    let module = target
        .symbols
        .find_module_for_address(target.kernel_dtb(), VirtAddr(offset));
    let symbol_module_is_hook = symbol
        .split_once('!')
        .is_some_and(|(module, _)| !is_nt_module(module));
    let hook = module
        .as_ref()
        .is_some_and(|module| !is_nt_module(&module.name))
        || symbol_module_is_hook;
    let chain = interrupt_chain_hint(target, offset);
    outln!(
        "  {:02x}: {} sel={:#06x} ist={} type={} dpl={} {}{}",
        vector,
        symbol,
        selector,
        ist,
        gate_name,
        dpl,
        if present { "present" } else { "not-present" },
        if hook { " [NON-NT HOOK]" } else { "" }
    );
    if let Some(chain) = chain {
        outln!("       chain: {chain}");
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

fn is_system_descriptor(raw: u64) -> bool {
    let system = raw & (1 << 44) == 0;
    let typ = (raw >> 40) & 0xf;
    system && matches!(typ, 0x2 | 0x9 | 0xb)
}

fn print_gdt_entry(index: usize, raw: u64, high: Option<u64>) {
    let limit = (raw & 0xffff) | (((raw >> 48) & 0xf) << 16);
    let granularity = raw & (1 << 55) != 0;
    let limit = if granularity {
        (limit << 12) | 0xfff
    } else {
        limit
    };
    let mut base =
        ((raw >> 16) & 0xffff) | (((raw >> 32) & 0xff) << 16) | (((raw >> 56) & 0xff) << 24);
    if let Some(high) = high {
        base |= (high & 0xffff_ffff) << 32;
    }
    let present = raw & (1 << 47) != 0;
    let dpl = (raw >> 45) & 0x3;
    let system = raw & (1 << 44) == 0;
    let typ = (raw >> 40) & 0xf;
    let long_mode = raw & (1 << 53) != 0;
    let default_size = raw & (1 << 54) != 0;
    outln!(
        "  {:>3}: base {} limit {:#x} type={:#x} {} dpl={} {}{}{}",
        index,
        ui::addr(base),
        limit,
        typ,
        if system { "system" } else { "code/data" },
        dpl,
        if present { "present" } else { "not-present" },
        if long_mode {
            " L"
        } else if default_size {
            " D/B"
        } else {
            ""
        },
        if granularity { " G" } else { "" }
    );
}
