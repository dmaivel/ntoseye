//! Per-processor kernel state: `_KPCR` / `_KPRCB` location and processor
//! count, shared by the CPU and scheduler commands, and the register
//! contexts the kernel saved in each `_KPRCB`, which a crash dump keeps.

use std::mem::offset_of;

use crate::arch::{Arch, amd64, arm64};
use crate::backend::dbg_backend::ThreadLayout;
use crate::backend::debugger_data::KdDebuggerData64;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::types::{MAX_PROCESSORS, VirtAddr};
use crate::nt::guest::Image;
use crate::nt::layout::ParsedType;
use crate::nt::target::Target;

fn kernel(target: &Target) -> Result<&Image> {
    Ok(&target.guest()?.ntoskrnl)
}

fn processor_block(target: &Target, index: u16) -> Result<VirtAddr> {
    if index >= MAX_PROCESSORS {
        return Err(Error::DebugInfo(format!(
            "processor index {index} exceeds the supported bound of {MAX_PROCESSORS}"
        )));
    }
    let nt = kernel(target)?;
    let symbol = nt.symbol("KiProcessorBlock")?;
    let memory = nt.memory();
    memory.read_pointer(symbol.address() + u64::from(index) * memory.arch().pointer_size())
}

fn prcb_offset(target: &Target) -> Result<u64> {
    kernel(target)?
        .types()
        .layout("_KPCR")?
        .field_offset("Prcb")
}

/// Where a processor's current thread keeps its TEB and address space, from
/// the kernel's PDB; `None` when a layout lacks one of the fields.
pub fn thread_layout(target: &Target) -> Option<ThreadLayout> {
    let types = kernel(target).ok()?.types();
    let current_thread = prcb_offset(target).ok()?
        + types
            .layout("_KPRCB")
            .ok()?
            .field_offset("CurrentThread")
            .ok()?;
    let thread = types.layout("_KTHREAD").ok()?;
    let process = thread.field_offset("ApcState").ok()?
        + types
            .layout("_KAPC_STATE")
            .ok()?
            .field_offset("Process")
            .ok()?;
    Some(ThreadLayout {
        current_thread,
        teb: thread.field_offset("Teb").ok()?,
        process,
        directory_table_base: types
            .layout("_KPROCESS")
            .ok()?
            .field_offset("DirectoryTableBase")
            .ok()?,
    })
}

fn validate_pointer(kind: &str, index: u16, value: VirtAddr) -> Result<VirtAddr> {
    if value.is_zero() {
        return Err(Error::DebugInfo(format!(
            "KiProcessorBlock[{index}] contains a null {kind}"
        )));
    }
    Ok(value)
}

/// Virtual address of processor `index`'s `_KPCR`. Resolved from
/// `nt!KiProcessorBlock[index]` (a `_KPRCB*`) minus `_KPCR.Prcb`'s offset on
/// both supported architectures. If the ARM64 PDB does not describe the
/// `Prcb` field, this returns an error while [`kprcb_for_processor`] remains
/// usable.
pub fn kpcr_for_processor(target: &Target, index: u16) -> Result<VirtAddr> {
    let entry = validate_pointer("processor pointer", index, processor_block(target, index)?)?;
    let offset = prcb_offset(target)?;
    let address = entry.0.checked_sub(offset).ok_or_else(|| {
        Error::DebugInfo(format!(
            "KiProcessorBlock[{index}] KPRCB underflows _KPCR.Prcb"
        ))
    })?;
    Ok(VirtAddr(address))
}

/// Virtual address of processor `index`'s `_KPRCB`. `KiProcessorBlock` stores
/// KPRCB pointers on both supported architectures.
pub fn kprcb_for_processor(target: &Target, index: u16) -> Result<VirtAddr> {
    validate_pointer("processor pointer", index, processor_block(target, index)?)
}

/// Number of processors the target reports (`nt!KeNumberProcessors`).
pub fn processor_count(target: &Target) -> Result<u16> {
    let nt = kernel(target)?;
    if let Ok(number_processors) = nt.symbol("KeNumberProcessors") {
        // KeNumberProcessors is a CCHAR/UCHAR. Never consume adjacent bytes
        // by speculatively reading it as a wider integer.
        if let Ok(value) = number_processors.read::<u8>()
            && value != 0
        {
            return Ok(u16::from(value));
        }
    }

    // A missing KeNumberProcessors is common in partial dumps. KiProcessorBlock
    // is a fixed-size pointer table; count its contiguous non-null entries with
    // a hard cap rather than probing arbitrary physical memory.
    let block = nt.symbol("KiProcessorBlock")?.address();
    let memory = nt.memory();
    let pointer_size = memory.arch().pointer_size();
    let mut count = 0u16;
    for index in 0..MAX_PROCESSORS {
        match memory.read_pointer(block + u64::from(index) * pointer_size) {
            Ok(entry) if !entry.is_zero() => count += 1,
            Ok(_) | Err(_) => break,
        }
    }
    if count != 0 {
        Ok(count)
    } else {
        Err(Error::DebugInfo(
            "processor count unavailable (KeNumberProcessors and KiProcessorBlock unreadable)"
                .into(),
        ))
    }
}

/// The register contexts the kernel saved in processors' `_KPRCB`s.
#[derive(Debug)]
pub struct PrcbContexts {
    /// Each processor's raw `CONTEXT`, by index; `None` where it could not
    /// be read.
    pub contexts: Vec<Option<Vec<u8>>>,
    /// Each processor's control and descriptor-table registers, which no
    /// `CONTEXT` records, by register-map name; empty where they could not
    /// be read.
    pub special_registers: Vec<Vec<(&'static str, u64)>>,
    /// Why a context, or the rest of them, could not be read.
    pub warnings: Vec<String>,
}

impl PrcbContexts {
    fn new(processors: usize) -> Self {
        Self {
            contexts: vec![None; processors],
            special_registers: vec![Vec::new(); processors],
            warnings: Vec::new(),
        }
    }

    /// Read each processor's `context_size`-byte context at the address
    /// `context_pointer` gives for its `_KPRCB`, warning of each one that
    /// cannot be read.
    fn read<F>(
        &mut self,
        target: &Target,
        context_size: usize,
        context_label: &str,
        context_pointer: F,
    ) -> Result<()>
    where
        F: Fn(VirtAddr) -> Result<VirtAddr>,
    {
        let memory = kernel(target)?.memory();
        for (i, slot) in self.contexts.iter_mut().enumerate() {
            let index = u16::try_from(i).map_err(|_| {
                Error::DebugInfo(format!("processor index {i} exceeds the supported bound"))
            })?;
            let prcb = match kprcb_for_processor(target, index) {
                Ok(prcb) => prcb,
                Err(error) => {
                    self.warnings
                        .push(format!("KiProcessorBlock[{i}] unavailable: {error}"));
                    continue;
                }
            };
            let context_ptr = match context_pointer(prcb) {
                Ok(context_ptr) if !context_ptr.is_zero() => context_ptr,
                Ok(_) => {
                    self.warnings
                        .push(format!("PRCB[{i}] Context pointer is null, skipping"));
                    continue;
                }
                Err(error) => {
                    self.warnings.push(format!(
                        "failed to read {context_label}[{i}] context pointer: {error}"
                    ));
                    continue;
                }
            };
            let mut context = vec![0u8; context_size];
            if let Err(error) = memory.read_bytes(context_ptr, &mut context) {
                self.warnings.push(format!(
                    "failed to read {context_label}[{i}] context: {error}"
                ));
                continue;
            }
            *slot = Some(context);
        }
        Ok(())
    }
}

/// `KDDEBUGGER_DATA64.OffsetPrcbContext` in the debugger data block at
/// `debugger_data`: where an AMD64 `_KPRCB` points to its context. `None`
/// when unreadable or zero.
pub fn prcb_context_offset(target: &Target, debugger_data: VirtAddr) -> Option<u16> {
    let memory = kernel(target).ok()?.memory();
    let field = offset_of!(KdDebuggerData64, offset_prcb_context) as u64;
    let offset: u16 = memory.read(debugger_data + field).ok()?;
    (offset > 0).then_some(offset)
}

/// Where processor `index`'s `_KPRCB` keeps the context the kernel saves
/// when it stops the processor, which a crash dump's reader takes the
/// processor's registers from: on AMD64 the `CONTEXT` its `Context` points
/// at (the field `KDDEBUGGER_DATA64.OffsetPrcbContext` names), on ARM64
/// its `ProcessorState.ContextFrame`.
pub fn prcb_context_address(target: &Target, index: u16) -> Result<VirtAddr> {
    let prcb = kprcb_for_processor(target, index)?;
    let address = match target.arch() {
        Arch::Amd64 => kernel(target)?
            .types()
            .struct_at("_KPRCB", prcb)?
            .read_pointer("Context")?,
        Arch::Arm64 => prcb + arm64_prcb_context_offset(target)?,
    };
    if address.is_zero() {
        return Err(Error::DebugInfo(format!(
            "processor {index}'s _KPRCB has no context"
        )));
    }
    Ok(address)
}

/// Processors `0..processors`' AMD64 contexts, each through the pointer at
/// `context_offset` in its `_KPRCB` (none without the offset), and the
/// special registers each `_KPRCB` saves.
pub fn read_amd64_prcb_contexts(
    target: &Target,
    processors: usize,
    context_offset: Option<u16>,
) -> PrcbContexts {
    let mut saved = PrcbContexts::new(processors);
    if let Some(context_offset) = context_offset {
        let read = kernel(target).and_then(|nt| {
            let memory = nt.memory();
            saved.read(target, amd64::CONTEXT_SIZE, "PRCB", |prcb| {
                memory.read(prcb + u64::from(context_offset))
            })
        });
        if let Err(error) = read {
            saved
                .warnings
                .push(format!("could not read PRCB contexts from dump: {error}"));
        }
    }
    // With none read, the registers are left out as unavailable; a
    // processor whose read failed beside others that did would show zeros,
    // so that one is named.
    let mut failures = Vec::new();
    for (index, slot) in saved.special_registers.iter_mut().enumerate() {
        let read = u16::try_from(index)
            .map_err(|_| Error::DebugInfo(format!("processor index {index} is out of range")))
            .and_then(|index| kprcb_for_processor(target, index))
            .and_then(|prcb| amd64_special_registers(target, prcb));
        match read {
            Ok(registers) => *slot = registers,
            Err(error) => failures.push(format!(
                "processor {index}'s control registers are unavailable: {error}"
            )),
        }
    }
    if failures.len() < saved.special_registers.len() {
        saved.warnings.extend(failures);
    }
    saved
}

/// The registers an AMD64 `_KSPECIAL_REGISTERS` saves that no `CONTEXT`
/// holds, each by its register-map name and field. `Cr3` is left out: a
/// dump's processors are served the kernel's page-table root.
const AMD64_SPECIAL_REGISTERS: [(&str, &str); 6] = [
    ("cr0", "Cr0"),
    ("cr2", "Cr2"),
    ("cr4", "Cr4"),
    ("cr8", "Cr8"),
    ("tr", "Tr"),
    ("ldtr", "Ldtr"),
];

/// The descriptor-table registers it saves, each a `_KDESCRIPTOR` field
/// whose limit and base the register map names apart.
const AMD64_SPECIAL_DESCRIPTORS: [(&str, &str, &str); 2] = [
    ("Gdtr", "gdtr_limit", "gdtr_base"),
    ("Idtr", "idtr_limit", "idtr_base"),
];

/// The control and descriptor-table registers the kernel saved in the AMD64
/// `_KPRCB` at `prcb` (`ProcessorState.SpecialRegisters`), by register-map
/// name. A crash dump's `CONTEXT` records carry none of them.
fn amd64_special_registers(target: &Target, prcb: VirtAddr) -> Result<Vec<(&'static str, u64)>> {
    let special = kernel(target)?
        .types()
        .struct_at("_KPRCB", prcb)?
        .embedded("ProcessorState")?
        .embedded("SpecialRegisters")?
        .prefetch();
    let mut registers = Vec::with_capacity(AMD64_SPECIAL_REGISTERS.len() + 4);
    for (register, field) in AMD64_SPECIAL_REGISTERS {
        registers.push((register, special.read_uint(field)?));
    }
    for (field, limit, base) in AMD64_SPECIAL_DESCRIPTORS {
        let descriptor = special.embedded(field)?;
        registers.push((limit, descriptor.read_uint("Limit")?));
        registers.push((base, descriptor.read_uint("Base")?));
    }
    Ok(registers)
}

/// Processors `0..processors`' ARM64 contexts, each its `_KPRCB`'s
/// `ProcessorState.ContextFrame`.
pub fn read_arm64_prcb_contexts(target: &Target, processors: usize) -> PrcbContexts {
    let mut saved = PrcbContexts::new(processors);
    let read = arm64_prcb_context_offset(target).and_then(|context_offset| {
        saved.read(target, arm64::CONTEXT_SIZE, "ARM64 PRCB", |prcb| {
            Ok(prcb + context_offset)
        })
    });
    if let Err(error) = read {
        saved.warnings.push(format!(
            "could not read ARM64 PRCB ContextFrame contexts from dump: {error}"
        ));
    }
    saved
}

/// The offset of `ProcessorState.ContextFrame` in an ARM64 `_KPRCB`.
fn arm64_prcb_context_offset(target: &Target) -> Result<u64> {
    let symbols = &target.symbols;
    let prcb = symbols
        .find_type_across_modules(target.kernel_dtb(), "_KPRCB")
        .ok_or_else(|| Error::StructNotFound("_KPRCB".into()))?;
    let processor_state = prcb.field("ProcessorState")?;
    let state_name = match &processor_state.type_data {
        ParsedType::Struct(name) | ParsedType::Union(name) => name,
        other => {
            return Err(Error::FieldTypeMismatch(
                format!("ProcessorState ({other})"),
                "struct".into(),
            ));
        }
    };
    let state = symbols
        .find_type_across_modules(target.kernel_dtb(), state_name)
        .ok_or_else(|| Error::StructNotFound(state_name.clone()))?;
    let context_frame = state.field("ContextFrame")?;
    let offset = processor_state.offset as u64 + context_frame.offset as u64;
    let context_end = offset
        .checked_add(arm64::CONTEXT_SIZE as u64)
        .ok_or_else(|| Error::DebugInfo("ARM64 PRCB ContextFrame offset overflow".into()))?;
    if context_end > prcb.size as u64 {
        return Err(Error::DebugInfo(format!(
            "ARM64 PRCB ContextFrame at {offset:#x} exceeds _KPRCB size {:#x}",
            prcb.size
        )));
    }
    Ok(offset)
}
