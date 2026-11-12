//! The x86 half of a WOW64 thread's stack. The 32-bit program's frames are
//! not on the native stack the walker unwinds: when x86 code leaves for
//! native code (a system call, a native or CHPE thunk), the WOW64 CPU layer
//! (`wow64cpu` on AMD64, the `xtajit` emulator on ARM64) saves its x86
//! registers in the thread's CPU area, and the native walk ends in that
//! layer. From the saved context the x86 frames are walked by their frame
//! pointers, which Windows' x86 system DLLs keep.

use std::collections::HashMap;

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Register};

use super::{
    FrameSource, RecoveredFrame, RecoveredStackTrace, ThreadTraceContext, expand_frame,
    nearest_symbol,
};
use crate::arch::amd64::COMPATIBILITY_MODE_CS;
use crate::base::memory::MemoryOps;
use crate::base::types::{CodeMachine, Dtb, VirtAddr};
use crate::nt::target::Target;

/// `WOW64_TLS_CPURESERVED`: the TLS slot of the 64-bit TEB that points at
/// the thread's CPU area, `{ u16 Flags; u16 Machine; }` then the context.
/// Windows 7's has a zero `ULONG` for that header.
const WOW64_TLS_CPURESERVED: u64 = 1;
const IMAGE_FILE_MACHINE_I386: u32 = 0x14c;
/// The x86 context follows the CPU area's 4-byte header.
const CPU_AREA_CONTEXT: u64 = 4;
/// `CONTEXT_i386`, which an x86 context's `ContextFlags` carry.
const CONTEXT_I386: u32 = 0x0001_0000;
/// `WOW64_CONTEXT` (x86 `CONTEXT`) offsets.
const CONTEXT_EBP: u64 = 0xb4;
const CONTEXT_EIP: u64 = 0xb8;
const CONTEXT_ESP: u64 = 0xc4;
/// How far above the saved `esp` a frame pointer may lie: an x86 thread's
/// stack reserve is 1 MiB unless the image asks for more.
const MAX_FRAME_DISTANCE: u64 = 16 << 20;
/// The modules the native walk leaves x86 code through.
const CPU_LAYER_MODULES: [&str; 2] = ["wow64cpu", "xtajit"];
/// How far above a stopped x86 thread's `esp` its return address is looked
/// for when `ebp` bounds nothing.
const RETURN_SCAN: u64 = 0x400;
/// How far into a function its prolog is looked for (see [`frame_is_set`]).
const PROLOG_WINDOW: u64 = 0x80;
/// The bytes before a return address that hold its call: x86's longest,
/// `call [disp32]` with a prefix, is 7.
const RETURN_CALL_BYTES: usize = 7;

/// Add the x86 frames of the thread whose TEB is `teb` to its native
/// `stack` after the last frame in the CPU layer, where the x86 code called
/// out. Only a stack that passed through that layer gets them: then the
/// saved context is where the x86 code left off, while a thread running x86
/// code has moved on from it. Only a WOW64 thread passes through it, and
/// only its CPU area names an x86 machine.
pub(super) fn add_x86_frames(
    debugger: &Target,
    trace: &ThreadTraceContext,
    teb: VirtAddr,
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
    let Some(frames) = x86_frames(debugger, trace, teb, limit) else {
        return;
    };
    let at = cpu_layer + 1;
    stack.frames.splice(at..at, frames);
    if stack.frames.len() > limit {
        stack.truncated += stack.frames.len() - limit;
        stack.frames.truncate(limit);
    }
}

/// `_TEB.TlsSlots`, from the kernel's layout, or ntdll's on a user-mode
/// minidump, which has no kernel.
fn tls_slots_offset(debugger: &Target, dtb: Dtb) -> Option<u64> {
    let layout = match debugger.guest() {
        Ok(guest) => guest.ntoskrnl.types().layout("_TEB"),
        Err(_) => debugger.types_in(dtb).layout("ntdll!_TEB"),
    };
    layout.ok()?.field_offset("TlsSlots").ok()
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
/// into the stub and `[esp]` returns into the caller, except that Windows 7
/// saves `esp` with the transition's return (`eip`) still on it. Then the
/// `ebp` chain, while it climbs the stack and holds plausible return
/// addresses.
fn walk_x86(
    u32_at: &dyn Fn(u64) -> Option<u32>,
    registers: X86Registers,
    in_image: &dyn Fn(u64) -> bool,
    limit: usize,
) -> Vec<(u64, u64, FrameSource)> {
    let X86Registers { eip, esp, ebp } = registers;
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
    } else if u32_at(esp).map(u64::from) == Some(eip) {
        caller_slot = esp + 4;
    }
    if let Some(caller) = return_in_image(caller_slot) {
        raw.push((caller, caller_slot + 4, FrameSource::Unwind));
    }
    follow_frame_pointers(u32_at, &mut raw, esp, ebp, limit);
    raw
}

/// `(ip, sp, source)` for each x86 frame of a thread stopped in its x86 code,
/// from its registers. Once the stopped function has set up its frame
/// (`frame_set`), its return address is `[ebp+4]`, and the locals below it
/// may hold stale ones. Before that, in its prolog, `ebp` is still the
/// caller's and `[esp]` need not be one (a pushed handler): the return
/// address is the first slot above `esp` that holds one (an address that
/// follows a call, `returns_after_call`), no further up than `[ebp+4]`.
/// Then the `ebp` chain.
fn walk_live_x86(
    u32_at: &dyn Fn(u64) -> Option<u32>,
    registers: X86Registers,
    returns_after_call: &dyn Fn(u64) -> bool,
    frame_set: bool,
    limit: usize,
) -> Vec<(u64, u64, FrameSource)> {
    let X86Registers { eip, esp, ebp } = registers;
    if eip == 0 || esp == 0 {
        return Vec::new();
    }
    let mut raw = vec![(eip, esp, FrameSource::Current)];
    let has_frame = ebp > esp && ebp - esp < MAX_FRAME_DISTANCE;
    let return_slot = |slot: u64| {
        u32_at(slot)
            .map(u64::from)
            .filter(|ret| returns_after_call(*ret))
            .map(|ret| (slot, ret))
    };
    let found = match return_slot(ebp + 4) {
        Some(found) if frame_set && has_frame => Some(found),
        _ => {
            let last_slot = if has_frame {
                ebp + 4
            } else {
                esp + RETURN_SCAN
            };
            (esp..=last_slot).step_by(4).find_map(return_slot)
        }
    };
    if let Some((slot, ret)) = found {
        raw.push((ret, slot + 4, FrameSource::Unwind));
    }
    follow_frame_pointers(u32_at, &mut raw, esp, ebp, limit);
    raw
}

/// Whether the x86 code from `function` up to `eip` has set up its frame:
/// `mov ebp, esp` ran, or a call, which in a prolog is to the `_SEH_prolog`
/// helper that sets it up. Past `PROLOG_WINDOW` the body is taken to have
/// one, as Windows' x86 system DLLs keep frame pointers.
fn frame_is_set(code: &[u8], function: u64, eip: u64) -> bool {
    let mut decoder = Decoder::with_ip(32, code, function, DecoderOptions::NONE);
    while decoder.can_decode() && decoder.ip() < eip {
        let instruction = decoder.decode();
        let ebp_from_esp = matches!(instruction.code(), Code::Mov_r32_rm32 | Code::Mov_rm32_r32)
            && instruction.op0_register() == Register::EBP
            && instruction.op1_register() == Register::ESP;
        if ebp_from_esp || instruction.flow_control() == FlowControl::Call {
            return true;
        }
    }
    false
}

/// Add to `raw` the frames of the `ebp` chain from `ebp`, while it climbs
/// the stack from `esp` and holds plausible return addresses, up to `limit`.
fn follow_frame_pointers(
    u32_at: &dyn Fn(u64) -> Option<u32>,
    raw: &mut Vec<(u64, u64, FrameSource)>,
    esp: u64,
    mut ebp: u64,
    limit: usize,
) {
    let mut previous = esp;
    while raw.len() < limit
        && ebp >= previous
        && ebp - esp < MAX_FRAME_DISTANCE
        && ebp.is_multiple_of(4)
    {
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
}

/// The x86 frames from the thread's saved context (see [`walk_x86`]).
fn x86_frames(
    debugger: &Target,
    trace: &ThreadTraceContext,
    teb: VirtAddr,
    limit: usize,
) -> Option<Vec<RecoveredFrame>> {
    let tls_slots = tls_slots_offset(debugger, trace.dtb())?;
    let memory = debugger.address_space(trace.dtb());
    let u32_at = |address: u64| memory.read::<u32>(VirtAddr(address)).ok();
    let area: u64 = memory
        .read(teb + tls_slots + WOW64_TLS_CPURESERVED * 8)
        .ok()?;
    let context = area + CPU_AREA_CONTEXT;
    let x86 = match u32_at(area)? {
        0 => u32_at(context)? & CONTEXT_I386 != 0,
        header => header >> 16 == IMAGE_FILE_MACHINE_I386,
    };
    if area == 0 || !x86 {
        return None;
    }
    let registers = X86Registers {
        eip: u64::from(u32_at(context + CONTEXT_EIP)?),
        esp: u64::from(u32_at(context + CONTEXT_ESP)?),
        ebp: u64::from(u32_at(context + CONTEXT_EBP)?),
    };
    let in_image = |address| trace.module_for_address(address).is_some();
    let raw = walk_x86(&u32_at, registers, &in_image, limit);
    (!raw.is_empty()).then(|| recovered_frames(debugger, trace, raw))
}

/// The frames of `raw` (see [`walk_x86`]), each with the `eip` and `esp` it
/// is at, its inline frames expanded.
fn recovered_frames(
    debugger: &Target,
    trace: &ThreadTraceContext,
    raw: Vec<(u64, u64, FrameSource)>,
) -> Vec<RecoveredFrame> {
    raw.into_iter()
        .flat_map(|(ip, sp, source)| {
            let returned = source == FrameSource::Unwind;
            expand_frame(debugger, trace, ip, sp, source, None, returned)
                .into_iter()
                .map(move |frame| RecoveredFrame {
                    frame,
                    registers: HashMap::from([("eip".to_string(), ip), ("esp".to_string(), sp)]),
                    frame_base: None,
                })
        })
        .collect()
}

/// The stack of a thread stopped in its x86 code, a WOW64 program's running
/// in compatibility mode, from the registers it stopped with (`values`):
/// the x86 code runs with their low halves, and no native unwind data
/// describes it (see [`walk_live_x86`]). Its first frame keeps every
/// register. `None` for a stop in native code.
pub(super) fn live_x86_stack(
    debugger: &Target,
    trace: &ThreadTraceContext,
    values: &HashMap<String, u64>,
    limit: usize,
) -> Option<RecoveredStackTrace> {
    if values.get("cs") != Some(&COMPATIBILITY_MODE_CS) {
        return None;
    }
    let low = |name: &str| values.get(name).map(|value| value & 0xffff_ffff);
    let registers = X86Registers {
        eip: low("rip")?,
        esp: low("rsp")?,
        ebp: low("rbp")?,
    };
    let memory = debugger.address_space(trace.dtb());
    let u32_at = |address: u64| memory.read::<u32>(VirtAddr(address)).ok();
    let returns_after_call = |ret: u64| {
        let mut before = [0u8; RETURN_CALL_BYTES];
        trace.module_for_address(ret).is_some()
            && ret
                .checked_sub(RETURN_CALL_BYTES as u64)
                .is_some_and(|at| memory.read_bytes(VirtAddr(at), &mut before).is_ok())
            && CodeMachine::X86.instruction_set().ends_in_call(&before)
    };
    let frame_set = nearest_symbol(debugger, trace.dtb(), VirtAddr(registers.eip))
        .map(|(_, _, offset)| u64::from(offset))
        .is_none_or(|offset| {
            let function = registers.eip - offset;
            let mut code = [0u8; PROLOG_WINDOW as usize];
            offset >= PROLOG_WINDOW
                || memory
                    .read_bytes(VirtAddr(function), &mut code[..offset as usize])
                    .is_ok_and(|()| frame_is_set(&code[..offset as usize], function, registers.eip))
        });
    let raw = walk_live_x86(&u32_at, registers, &returns_after_call, frame_set, limit);
    let mut frames = recovered_frames(debugger, trace, raw);
    // Inline frames come on top of the walked ones, so the limit applies again.
    let truncated = frames.len().saturating_sub(limit);
    frames.truncate(limit);
    if let Some(first) = frames.first_mut() {
        first.registers = values.clone();
    }
    Some(RecoveredStackTrace {
        frames,
        truncated,
        dtb: trace.dtb(),
        thread: None,
    })
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

        // Windows 7 on AMD64: `esp` still holds the transition's return,
        // which is `eip`, and the caller's is above it.
        let registers = X86Registers {
            esp: 0x39f458,
            ..registers
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

    /// A WOW64 ping stopped in x86 `kernelbase!SleepEx`'s prolog, before
    /// `_SEH_prolog4` sets up its frame: `[esp]` is the exception handler it
    /// pushed, a code address no call precedes, and `ebp` is still its
    /// caller's. The return into `Sleep` is found above it, then the chain.
    /// Once a function has its frame, its return is `[ebp+4]`, whatever its
    /// locals hold, and is not listed twice.
    #[test]
    fn a_live_x86_stop_finds_its_return_then_the_frame_chain() {
        let stack: HashMap<u64, u32> = HashMap::from([
            (0x5eef08, 0x7662_1a30), // the pushed handler, kernelbase!_except_handler4
            (0x5eef0c, 0x38),
            (0x5eef10, 0x7652_a18f), // return into kernelbase!Sleep+0xf
            (0x5eef1c, 0x5eef30),    // Sleep's frame: saved ebp
            (0x5eef20, 0x0005_316c), // return into ping!wmain+0xec9
            (0x5eef30, 0x5eff00),
            (0x5eef34, 0x0005_33a0), // return into ping!__wmainCRTStartup
        ]);
        let u32_at = |address: u64| stack.get(&address).copied();
        let after_call = |ret: u64| [0x7652_a18f, 0x0005_316c, 0x0005_33a0].contains(&ret);
        let ips = |registers, frame_set| -> Vec<u64> {
            walk_live_x86(&u32_at, registers, &after_call, frame_set, 16)
                .iter()
                .map(|(ip, _, _)| *ip)
                .collect()
        };

        let in_prolog = X86Registers {
            eip: 0x7652_a1a7,
            esp: 0x5eef08,
            ebp: 0x5eef1c,
        };
        assert_eq!(
            ips(in_prolog, false),
            [0x7652_a1a7, 0x7652_a18f, 0x0005_316c, 0x0005_33a0]
        );

        // In Sleep's body, its frame set: its return is [ebp+4], though its
        // locals below hold a stale return of an earlier call.
        let in_body = X86Registers {
            eip: 0x7652_a189,
            esp: 0x5eef08,
            ebp: 0x5eef1c,
        };
        assert_eq!(ips(in_body, true), [0x7652_a189, 0x0005_316c, 0x0005_33a0]);
    }
}
