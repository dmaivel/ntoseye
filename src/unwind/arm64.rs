//! ARM64 unwinding: `.pdata` function-range lookup and the frame-pointer
//! (x29) chain walk.

use std::collections::HashMap;
use std::ops::Range;

use super::walk::{ensure_frame_module_symbols, record_recovered_frame};
use super::{
    FrameSource, MAX_UNWIND_FRAMES, RecoveredFrame, RecoveredStackTrace, RegisterContext,
    StackFrame, format_symbol, frame_source_location, image_u32, resolve_thread_trace_context,
};
use crate::{backend::MemoryOps, gdb::RegisterMap, pe::PeImage, target::Target, types::VirtAddr};

/// Decode an ARM64 `.pdata` entry's function length. Packed entries carry an
/// 11-bit instruction count in the entry itself; unpacked entries point to an
/// `.xdata` header whose low 18 bits carry the instruction count.
fn arm64_function_length(image: &PeImage, unwind_data: u32) -> Option<u32> {
    let instructions = match unwind_data & 0b11 {
        0 => {
            let xdata_rva = (unwind_data & !0b11) as usize;
            let header = image_u32(&image.read(xdata_rva, 4)?, 0)?;
            header & 0x3ffff
        }
        1 | 2 => (unwind_data >> 2) & 0x7ff,
        _ => return None,
    };
    (instructions != 0).then(|| instructions * 4)
}

/// Find the ARM64 runtime-function entry containing `rva` in the exception
/// directory at `pdata`. ARM64 `.pdata` records are sorted 8-byte
/// `{BeginAddress, UnwindData}` pairs; unlike AMD64, the end address must be
/// decoded from packed unwind data or the `.xdata` header.
pub(super) fn lookup_arm64_runtime_function(
    image: &PeImage,
    pdata: Range<usize>,
    rva: u32,
) -> Option<(u32, u32)> {
    let entry = |index: usize| image.read(pdata.start + index * 8, 8);
    let count = pdata.len() / 8;
    let mut low = 0usize;
    let mut high = count;
    while low < high {
        let mid = low + (high - low) / 2;
        let begin = image_u32(&entry(mid)?, 0)?;
        if begin <= rva {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    let index = low.checked_sub(1)?;
    let found = entry(index)?;
    let begin = image_u32(&found, 0)?;
    let unwind_data = image_u32(&found, 4)?;
    let end = begin.checked_add(arm64_function_length(image, unwind_data)?)?;
    (rva >= begin && rva < end).then_some((begin, end))
}

/// Strip AArch64 pointer-authentication bits (bits 63:56) from a return
/// address: sign-extend the 56-bit canonical address back to 64 bits.
fn strip_pac(addr: u64) -> u64 {
    ((addr << 8) as i64 >> 8) as u64
}

/// ARM64 backtrace via the frame-pointer (x29) chain: each frame stores the
/// previous FP at `[fp]` and the return address at `[fp+8]`. Windows ARM64
/// kernel code keeps frame pointers enabled, so this is reliable; PAC-signed
/// return addresses are stripped.
pub(super) fn build_recovered_stacktrace_arm64(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    limit: usize,
) -> RecoveredStackTrace {
    let limit = limit.max(1);
    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), regs)
        .unwrap_or(0);
    let trace = resolve_thread_trace_context(debugger, cr3);
    let seed_pc = register_map.read_u64("rip", regs).unwrap_or(0);
    let seed_sp = register_map.read_u64("rsp", regs).unwrap_or(0);
    let mut seed_context = RegisterContext::from_registers(register_map, regs);
    seed_context.rip = seed_pc;
    seed_context.rsp = seed_sp;
    let mut fp = register_map.read_u64("fp", regs).unwrap_or(0);
    let mut raw: Vec<(RegisterContext, FrameSource, u64)> =
        vec![(seed_context, FrameSource::Current, fp)];

    let memory = debugger.address_space(trace.active_dtb);
    for _ in 0..MAX_UNWIND_FRAMES {
        if raw.len() >= limit {
            break;
        }
        let mut buf = [0u8; 16];
        if memory.read_bytes(VirtAddr(fp), &mut buf).is_err() {
            break;
        }
        let mut next_fp_bytes = [0u8; 8];
        next_fp_bytes.copy_from_slice(&buf[..8]);
        let next_fp = u64::from_le_bytes(next_fp_bytes);
        let mut return_address_bytes = [0u8; 8];
        return_address_bytes.copy_from_slice(&buf[8..]);
        let ra = strip_pac(u64::from_le_bytes(return_address_bytes));
        if ra == 0 || next_fp == 0 || next_fp <= fp {
            break;
        }
        let mut context = RegisterContext::from_registers(register_map, regs);
        context.rip = ra;
        context.rsp = fp.wrapping_add(16);
        context.regs = [None; 16];
        raw.push((context, FrameSource::Unwind, next_fp));
        fp = next_fp;
    }

    ensure_frame_module_symbols(
        debugger,
        &trace,
        raw.iter().map(|(context, _, _)| context.rip),
    );

    let initial_registers = register_map.to_hashmap(regs);
    let mut stacktrace = RecoveredStackTrace::new(&trace);
    for (index, (context, source, fp)) in raw.into_iter().enumerate() {
        let mut registers;
        if index == 0 {
            registers = initial_registers.clone();
        } else {
            registers = HashMap::new();
            if let Some(dtb) = initial_registers.get(debugger.arch().dtb_register()) {
                let name = debugger.arch().dtb_register();
                registers.insert(name.to_string(), *dtb);
            }
            registers.insert("fp".to_string(), fp);
            registers.insert("sp".to_string(), context.rsp);
            registers.insert("pc".to_string(), context.rip);
        }
        let frame = StackFrame {
            sp: context.rsp,
            ip: context.rip,
            symbol: format_symbol(debugger, &trace, context.rip),
            source,
            source_location: frame_source_location(debugger, &trace, context.rip),
        };
        record_recovered_frame(
            &mut stacktrace,
            limit,
            RecoveredFrame {
                frame,
                registers,
                frame_base: (fp != 0).then_some(fp),
            },
        );
    }
    stacktrace
}

#[cfg(test)]
mod tests {
    use super::lookup_arm64_runtime_function;
    use crate::pe::PeImage;

    #[test]
    fn lookup_arm64_runtime_function_decodes_packed_and_xdata_lengths() {
        let mut image_bytes = vec![0u8; 0x3100];
        // Full .xdata header: low 18 bits are a 0x80-byte function in 4-byte units.
        image_bytes[0x2000..0x2004].copy_from_slice(&(0x80u32 / 4).to_le_bytes());

        let mut pdata = Vec::new();
        // Packed entry: flag 1 and a 0x40-byte function length.
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&(((0x40u32 / 4) << 2) | 1).to_le_bytes());
        // Unpacked entry: flag 0 and an RVA to the .xdata header above.
        pdata.extend_from_slice(&0x1100u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        image_bytes[0x3000..0x3000 + pdata.len()].copy_from_slice(&pdata);
        let image = PeImage::complete(image_bytes);
        let pdata = 0x3000..0x3000 + pdata.len();

        assert_eq!(
            lookup_arm64_runtime_function(&image, pdata.clone(), 0x103c),
            Some((0x1000, 0x1040))
        );
        assert!(lookup_arm64_runtime_function(&image, pdata.clone(), 0x1040).is_none());
        assert_eq!(
            lookup_arm64_runtime_function(&image, pdata.clone(), 0x117c),
            Some((0x1100, 0x1180))
        );
        assert!(lookup_arm64_runtime_function(&image, pdata, 0x1180).is_none());
    }
}
