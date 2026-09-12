//! Per-processor kernel state: `_KPCR` / `_KPRCB` location and processor
//! count, shared by the CPU and scheduler commands.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::VirtAddr;

/// Upper bound on processor indexes; `KiProcessorBlock` is sized by
/// `MAXIMUM_PROCESSORS`.
pub const MAX_PROCESSORS: u16 = 2048;

fn kernel(target: &Target) -> Result<&crate::guest::WinObject> {
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
    nt.memory().read(symbol.address() + (u64::from(index) * 8))
}

fn prcb_offset(target: &Target) -> Result<u64> {
    kernel(target)?
        .types()
        .layout("_KPCR")?
        .field_offset("Prcb")
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
    let mut count = 0u16;
    for index in 0..MAX_PROCESSORS {
        match memory.read::<VirtAddr>(block + (u64::from(index) * 8)) {
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
