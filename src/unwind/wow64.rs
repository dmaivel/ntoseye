//! The x86 half of a WOW64 thread's stack. The 32-bit program's frames are
//! not on the native stack the walker unwinds: when x86 code leaves for
//! native code (a system call, a native or CHPE thunk), the WOW64 CPU layer
//! (`wow64cpu` on AMD64, the `xtajit` emulator on ARM64) saves its x86
//! registers in the thread's CPU area, and the native walk ends in that
//! layer. From the saved context the x86 frames are walked by their frame
//! pointers, which Windows' x86 system DLLs keep.

use std::collections::HashMap;

use super::{
    FrameSource, RecoveredFrame, RecoveredStackTrace, StackFrame, ThreadTraceContext,
    format_symbol, frame_source_location,
};
use crate::backend::MemoryOps;
use crate::target::{Target, ThreadInfo};
use crate::types::VirtAddr;

/// `WOW64_TLS_CPURESERVED`: the TLS slot of the 64-bit TEB that points at
/// the thread's CPU area, `{ u16 Flags; u16 Machine; }` then the context.
const WOW64_TLS_CPURESERVED: u64 = 1;
const IMAGE_FILE_MACHINE_I386: u32 = 0x14c;
/// The x86 context follows the CPU area's 4-byte header.
const CPU_AREA_CONTEXT: u64 = 4;
/// `WOW64_CONTEXT` (x86 `CONTEXT`) offsets.
const CONTEXT_EBP: u64 = 0xb4;
const CONTEXT_EIP: u64 = 0xb8;
const CONTEXT_ESP: u64 = 0xc4;
/// How far above the saved `esp` a frame pointer may lie: an x86 thread's
/// stack reserve is 1 MiB unless the image asks for more.
const MAX_FRAME_DISTANCE: u64 = 16 << 20;
/// The modules the native walk leaves x86 code through.
const CPU_LAYER_MODULES: [&str; 2] = ["wow64cpu", "xtajit"];

/// Add `thread`'s x86 frames to its native `stack` after the last frame in
/// the CPU layer, where the x86 code called out. Only a stack that passed
/// through that layer gets them: then the saved context is where the x86
/// code left off, while a thread running x86 code has moved on from it.
pub(super) fn add_x86_frames(
    debugger: &Target,
    trace: &ThreadTraceContext,
    thread: &ThreadInfo,
    stack: &mut RecoveredStackTrace,
    limit: usize,
) {
    let Some(cpu_layer) = stack.frames.iter().rposition(|frame| {
        trace
            .module_for_address(frame.frame.ip)
            .is_some_and(|module| {
                CPU_LAYER_MODULES
                    .iter()
                    .any(|name| module.info.short_name.eq_ignore_ascii_case(name))
            })
    }) else {
        return;
    };
    if !is_wow64_thread(debugger, thread) {
        return;
    }
    let Some(frames) = x86_frames(debugger, trace, thread, limit) else {
        return;
    };
    let at = cpu_layer + 1;
    stack.frames.splice(at..at, frames);
    if stack.frames.len() > limit {
        stack.truncated += stack.frames.len() - limit;
        stack.frames.truncate(limit);
    }
}

fn is_wow64_thread(debugger: &Target, thread: &ThreadInfo) -> bool {
    let (Some(eprocess), Ok(guest)) = (thread.eprocess, debugger.guest()) else {
        return false;
    };
    let Ok(layout) = guest.ntoskrnl.types().layout("_EPROCESS") else {
        return false;
    };
    debugger
        .read_kernel_layout_field::<u64>(&layout, eprocess, "WoW64Process")
        .is_ok_and(|wow64| wow64 != 0)
}

#[derive(Clone, Copy)]
struct X86Registers {
    eip: u64,
    esp: u64,
    ebp: u64,
}

/// `(ip, sp, source)` for each x86 frame from a saved context. The x86 code
/// left through a frameless stub (`Nt*`: `call [Wow64Transition]`), so the
/// stub's caller is found on the stack, not through `ebp`: on ARM64 `eip` is
/// the transition itself, outside any image, and `[esp]` returns into the
/// stub, `[esp+4]` into its caller; on AMD64 `eip` is already that return
/// into the stub and `[esp]` returns into the caller. Then the `ebp` chain,
/// while it climbs the stack and holds plausible return addresses.
fn walk_x86(
    u32_at: &dyn Fn(u64) -> Option<u32>,
    registers: X86Registers,
    in_image: &dyn Fn(u64) -> bool,
    limit: usize,
) -> Vec<(u64, u64, FrameSource)> {
    let X86Registers { eip, esp, mut ebp } = registers;
    if eip == 0 || esp == 0 {
        return Vec::new();
    }
    let mut raw = vec![(eip, esp, FrameSource::Seed)];
    let return_in_image = |slot: u64| u32_at(slot).map(u64::from).filter(|ret| in_image(*ret));
    let mut caller_slot = esp;
    if !in_image(eip)
        && let Some(stub) = return_in_image(esp)
    {
        raw.push((stub, esp + 4, FrameSource::Unwind));
        caller_slot = esp + 4;
    }
    if let Some(caller) = return_in_image(caller_slot) {
        raw.push((caller, caller_slot + 4, FrameSource::Unwind));
    }
    let mut previous = esp;
    while raw.len() < limit && ebp >= previous && ebp - esp < MAX_FRAME_DISTANCE && ebp % 4 == 0 {
        let Some(ret) = u32_at(ebp + 4)
            .map(u64::from)
            .filter(|ret| *ret >= 0x1_0000)
        else {
            break;
        };
        // A frameless function's caller is already listed from the stack.
        if raw.last().is_none_or(|(ip, _, _)| *ip != ret) {
            raw.push((ret, ebp + 8, FrameSource::Unwind));
        }
        let Some(next) = u32_at(ebp).map(u64::from) else {
            break;
        };
        previous = ebp + 8;
        ebp = next;
    }
    raw.truncate(limit);
    raw
}

/// The x86 frames from the thread's saved context (see [`walk_x86`]).
fn x86_frames(
    debugger: &Target,
    trace: &ThreadTraceContext,
    thread: &ThreadInfo,
    limit: usize,
) -> Option<Vec<RecoveredFrame>> {
    let teb = thread.teb?;
    let tls_slots = debugger
        .guest()
        .ok()?
        .ntoskrnl
        .types()
        .layout("_TEB")
        .ok()?
        .field_offset("TlsSlots")
        .ok()?;
    let memory = debugger.address_space(trace.dtb());
    let u32_at = |address: u64| memory.read::<u32>(VirtAddr(address)).ok();
    let area: u64 = memory
        .read(teb + tls_slots + WOW64_TLS_CPURESERVED * 8)
        .ok()?;
    if area == 0 || u32_at(area)? >> 16 != IMAGE_FILE_MACHINE_I386 {
        return None;
    }
    let context = area + CPU_AREA_CONTEXT;
    let registers = X86Registers {
        eip: u64::from(u32_at(context + CONTEXT_EIP)?),
        esp: u64::from(u32_at(context + CONTEXT_ESP)?),
        ebp: u64::from(u32_at(context + CONTEXT_EBP)?),
    };
    let in_image = |address| trace.module_for_address(address).is_some();
    let raw = walk_x86(&u32_at, registers, &in_image, limit);
    if raw.is_empty() {
        return None;
    }

    Some(
        raw.into_iter()
            .map(|(ip, sp, source)| RecoveredFrame {
                frame: StackFrame {
                    sp,
                    ip,
                    symbol: format_symbol(debugger, trace, ip),
                    source,
                    source_location: frame_source_location(debugger, trace, ip),
                    machine_frame: None,
                },
                registers: HashMap::from([("eip".to_string(), ip), ("esp".to_string(), sp)]),
                frame_base: None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cmd.exe on ARM64 Windows, waiting on a child: x86 `ntdll32!NtWaitFor
    /// SingleObject` called the WOW64 transition stub (`eip`, in no image)
    /// from a frameless stub, whose caller's frame starts the `ebp` chain.
    #[test]
    fn a_system_call_lists_the_stub_its_caller_and_the_frame_chain() {
        let stack: HashMap<u64, u32> = HashMap::from([
            (0x39f458, 0x778b_904c), // return into ntdll32!NtWaitForSingleObject
            (0x39f45c, 0x771e_7860), // its return into the caller
            (0x39f470, 0x39f4d0),    // saved ebp
            (0x39f474, 0x7708_8fb4), // kernelbase!#WaitForSingleObjectEx+0xe4
            (0x39f4d0, 0x39f500),
            (0x39f4d4, 0x771d_560c), // kernelbase!WaitForSingleObject$pop_thunk+0x20
            (0x39f500, 0x39f4f0),    // a chain that turns back down ends here
            (0x39f504, 0x0051_a52c), // cmd!WaitProcAndCloseHandle+0x1d
        ]);
        let u32_at = |address: u64| stack.get(&address).copied();
        let registers = X86Registers {
            eip: 0x21_0002,
            esp: 0x39f458,
            ebp: 0x39f470,
        };
        let frames = walk_x86(&u32_at, registers, &|address| address != 0x21_0002, 16);
        let ips: Vec<u64> = frames.iter().map(|(ip, _, _)| *ip).collect();
        assert_eq!(
            ips,
            [
                0x21_0002,
                0x778b_904c,
                0x771e_7860,
                0x7708_8fb4,
                0x771d_560c,
                0x0051_a52c
            ]
        );
        assert_eq!(frames[0].2, FrameSource::Seed);

        // AMD64: `eip` is the return into the stub, and `[esp]` its return
        // into the caller, which the `ebp` chain would skip.
        let registers = X86Registers {
            eip: 0x778b_904c,
            esp: 0x39f45c,
            ebp: 0x39f470,
        };
        let frames = walk_x86(&u32_at, registers, &|_| true, 16);
        let ips: Vec<u64> = frames.iter().map(|(ip, _, _)| *ip).collect();
        assert_eq!(
            ips,
            [
                0x778b_904c,
                0x771e_7860,
                0x7708_8fb4,
                0x771d_560c,
                0x0051_a52c
            ]
        );
    }
}
