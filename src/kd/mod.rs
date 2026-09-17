use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::{ErrorKind, Write};
use std::mem::take;
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
#[cfg(test)]
use std::thread::JoinHandle;
use std::thread::spawn;
use std::time::{Duration, Instant};

use crate::backend::MemoryOps;
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, ContinueDisposition, DebugBackend, DebugCapability, DebugLog,
    DebugOutputPage, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, StopEvent,
};
use crate::debugger_data::{DebuggerDataCandidate, MetadataSource};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::kd::framing::{BREAKIN_BYTE, KdFraming};
use crate::memory::{AddressSpace, PAGE_SIZE, TranslationCache};
use crate::phys::PhysMem;
use crate::session::clear_trap_flag;
use crate::types::{Arch, Dtb, PhysAddr, VirtAddr};

macro_rules! kd_trace {
    ($($arg:tt)*) => {
        if $crate::kd::trace_enabled() {
            eprintln!("[{:>9.3}] {}", $crate::kd::trace_elapsed().as_secs_f64(), format_args!($($arg)*));
        }
    };
}

macro_rules! kd_trace_bytes {
    ($($arg:tt)*) => {
        if $crate::kd::trace_bytes_enabled() {
            eprint!($($arg)*);
        }
    };
}

pub fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_KD_TRACE").is_some())
}

/// Seconds since the first trace line, so a trace shows what each request
/// costs on the wire.
pub fn trace_elapsed() -> Duration {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed()
}

pub fn trace_bytes_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_KD_TRACE_BYTES").is_some())
}

pub mod api;
pub mod context;
pub mod context_arm64;
pub mod framing;
pub mod hwbp;
mod kdnet;
mod transport;
use kdnet::KdNetStream;
use transport::KdTransport;

mod debug_io;
pub use debug_io::*;
mod file_io;
pub use file_io::*;
mod event_loop;
pub use event_loop::*;
pub mod wire;

#[derive(Debug, Clone)]
pub struct StateChange {
    processor: u16,
    number_processors: u16,
    new_state: u32,
    exception_code: u32,
    exception_first_chance: Option<bool>,
    exception_address: Option<u64>,
    program_counter: u64,
    kernel_base_hint: Option<VirtAddr>,
    is_bugcheck: bool,
    bugcheck: Option<BugcheckInfo>,
    target_reloaded: bool,
    assisted_breakin: bool,
}

#[derive(Debug, Clone, Copy)]
struct PendingWriteBreakpoint {
    addr: u64,
    processor: u16,
}

/// Retained guest debug-output lines (DbgPrint ring). Bounded so a chatty guest
/// can't grow memory without limit; older lines are evicted and a reader that
/// falls behind sees `dropped`.
const DEBUG_LOG_CAPACITY: usize = 4096;
/// [`KdBackend::running_reason`] when the operator picked `--memory-source kd`.
const MEMORY_OVER_KD_CHOSEN: &str = "Guest memory is read over KD on this session, and KD only \
     answers while the target is halted (--memory-source auto reads host memory live).";
/// [`KdBackend::running_reason`] when `auto` found no usable host memory.
const MEMORY_OVER_KD_FALLBACK: &str = "Guest memory is read over KD on this session (host memory \
     was unavailable at connect), and KD only answers while the target is halted.";

const DBG_KD_EXCEPTION_STATE_CHANGE: u32 = 0x0000_3030;
/// Symbol load/unload notification. The kernel emits these (including during
/// bugcheck via KiBugcheckUnloadDebugSymbols); WinDbg acknowledges and resumes
/// rather than presenting a user break
const DBG_KD_LOAD_SYMBOLS_STATE_CHANGE: u32 = 0x0000_3031;
/// Command-string notification (e.g. `.echo` from the target); also transparent
const DBG_KD_COMMAND_STRING_STATE_CHANGE: u32 = 0x0000_3032;

const AMD64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;
/// Control-space bases are selectors: 0 returns a KPCR pointer, 2 selects
/// `KARM64_SPECIAL_REGISTERS` (160 bytes in the public WoA definition).
const ARM64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;

fn detect_arch(machine_type: u16) -> Result<Arch> {
    match Arch::from_machine_type(machine_type) {
        Some(arch) => Ok(arch),
        None => {
            let name = match machine_type {
                0x014c => "I386",
                _ => "unknown",
            };
            Err(Error::UnsupportedArchitecture(format!(
                "{name} KD target (machine {machine_type:#06x})"
            )))
        }
    }
}
const KSPECIAL_REGISTERS_CR0_OFFSET: usize = 0x00;
const KSPECIAL_REGISTERS_CR2_OFFSET: usize = 0x08;
const KSPECIAL_REGISTERS_CR3_OFFSET: usize = 0x10;
const KSPECIAL_REGISTERS_CR4_OFFSET: usize = 0x18;
const KSPECIAL_REGISTERS_DR0_OFFSET: usize = 0x20;
const KSPECIAL_REGISTERS_DR1_OFFSET: usize = 0x28;
const KSPECIAL_REGISTERS_DR2_OFFSET: usize = 0x30;
const KSPECIAL_REGISTERS_DR3_OFFSET: usize = 0x38;
const KSPECIAL_REGISTERS_DR6_OFFSET: usize = 0x40;
const KSPECIAL_REGISTERS_DR7_OFFSET: usize = 0x48;
// KDESCRIPTOR has Pad[3], Limit, and Base, so its Base is eight bytes into
// the descriptor even though the descriptor itself starts at these offsets.
const KSPECIAL_REGISTERS_GDTR_OFFSET: usize = 0x50;
const KSPECIAL_REGISTERS_IDTR_OFFSET: usize = 0x60;
const KSPECIAL_REGISTERS_TR_OFFSET: usize = 0x70;
const KSPECIAL_REGISTERS_LDTR_OFFSET: usize = 0x72;
const KSPECIAL_REGISTERS_CR8_OFFSET: usize = 0xA0;
const KSPECIAL_REGISTERS_MIN_SIZE: usize = KSPECIAL_REGISTERS_CR8_OFFSET + 8;
const ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET: usize = 0x28;
const ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET: usize = 0x68;
const ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET: usize = 0x88;
const ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET: usize = 0x98;
const ARM64_KSPECIAL_REGISTERS_MIN_SIZE: usize = 0xA0;
const MSR_EFER: u32 = 0xC000_0080;
const STATUS_BREAKPOINT: u32 = 0x8000_0003;
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
const KD_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const KD_INITIAL_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const DBGKD_DEBUG_IO_HEADER_SIZE: usize = 16;
const DBGKD_DEBUG_IO_MIN_HEADER_SIZE: usize = 12;
const DBGKD_PRINT_STRING_API: u32 = 0x0000_3230;
const DBGKD_GET_STRING_API: u32 = 0x0000_3231;
const DBGKD_FILE_IO_HEADER_SIZE: usize = 64;
const DBGKD_CREATE_FILE_API: u32 = 0x0000_3430;
const DBGKD_READ_FILE_API: u32 = 0x0000_3431;
const DBGKD_WRITE_FILE_API: u32 = 0x0000_3432;
const DBGKD_CLOSE_FILE_API: u32 = 0x0000_3433;
const STATUS_UNSUCCESSFUL: u32 = 0xc000_0001;
/// Entries in the target's `KdpBreakpointTable`. A fixed global in every
/// Windows kernel (`BREAKPOINT_TABLE_SIZE`), and the ceiling on how many
/// software breakpoints any debugger can have installed at once.
const KD_BREAKPOINT_TABLE_SIZE: u32 = 32;
const KD_REFRESH_MESSAGE: &[u8] = b"KDTARGET: Refreshing KD connection";
const KD_INITIAL_TIMEOUT_ENV: &str = "NTOSEYE_KD_TIMEOUT";
const KD_INITIAL_TIMEOUT_DEFAULT: Duration = Duration::from_secs(8);
const KD_INITIAL_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);
const KD_RECONNECT_BREAKIN_INTERVAL: Duration = Duration::from_millis(250);
const KD_RECONNECT_BREAKIN_TRACE_EVERY: u32 = 8;
const POST_BUGCHECK_RECONNECT_ASSIST_DELAY: Duration = Duration::from_secs(20);
const KD_EXIT_STOP_POLL: Duration = Duration::from_secs(1);
const KD_EXIT_MAX_CONTINUES: u32 = 8;
/// How long the background pump blocks on a socket read before looping back to
/// check its shutdown flag. Incoming packets are still serviced immediately
/// (this only bounds shutdown latency); the kernel writes each packet as one
/// burst, so a timeout this size only ever fires in the idle gap between packets.
const PUMP_POLL: Duration = Duration::from_millis(100);
const KD_REMOTE_MEMORY_CHUNK: usize = 0x800;
/// Unit of [`LineCache`]. A serial link pays per byte (a QEMU UART
/// exits the guest for each one: about 2 ms per request plus 5 us per
/// byte), so a line is sized to pay for itself after a few field reads
/// rather than to fill a request.
const KD_VIRTUAL_LINE: usize = 0x200;
/// Lines a [`LineCache`] holds before starting over; 16 MiB of guest
/// memory, past what one halt's commands read short of an image scan.
const LINE_CACHE_LIMIT: usize = 32768;
/// Windows KD encoding of `TTBR1_EL1`: op0=3, op1=0, CRn=2, CRm=0, op2=1.
const ARM64_WINDBG_TTBR1_EL1: u32 = 0x0003_0201;
/// Windows KD encodings of ARM64 system registers (op0/op1/CRn/CRm/op2).
const ARM64_WINDBG_TTBR0_EL1: u32 = 0x0003_0200;
const ARM64_WINDBG_ESR_EL1: u32 = 0x0003_0520;
const ARM64_WINDBG_FAR_EL1: u32 = 0x0003_0600;

const ARM64_DEBUG_REGISTER_OFFSETS: &[(usize, usize, usize, usize)] = &[
    (
        ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET,
        context_arm64::OFFSET_BVR0,
        8,
        hwbp::ARM64_MAX_BREAKPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET,
        context_arm64::OFFSET_BCR0,
        4,
        hwbp::ARM64_MAX_BREAKPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET,
        context_arm64::OFFSET_WVR0,
        8,
        hwbp::ARM64_MAX_WATCHPOINTS as usize,
    ),
    (
        ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET,
        context_arm64::OFFSET_WCR0,
        4,
        hwbp::ARM64_MAX_WATCHPOINTS as usize,
    ),
];

fn normalize_kernel_dtb(arch: Arch, register_value: u64) -> Dtb {
    register_value & arch.dtb_page_mask()
}

fn kspecial_control_space(arch: Arch) -> (u64, usize) {
    match arch {
        Arch::Amd64 => (
            AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
            KSPECIAL_REGISTERS_MIN_SIZE,
        ),
        Arch::Arm64 => (
            ARM64_DEBUG_CONTROL_SPACE_KSPECIAL,
            ARM64_KSPECIAL_REGISTERS_MIN_SIZE,
        ),
    }
}

fn arm64_slot_offsets(slot: u8) -> Result<(usize, usize)> {
    if hwbp::ARM64_WATCHPOINT_SLOTS.contains(&slot) {
        Ok((
            ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET + slot as usize * 8,
            ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET + slot as usize * 4,
        ))
    } else if hwbp::ARM64_BREAKPOINT_SLOTS.contains(&slot) {
        let index = (slot - hwbp::ARM64_BREAKPOINT_SLOTS.start) as usize;
        Ok((
            ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET + index * 8,
            ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET + index * 4,
        ))
    } else {
        Err(Error::Kd(format!(
            "invalid ARM64 hardware breakpoint slot {slot} (expected 0-{})",
            hwbp::ARM64_BREAKPOINT_SLOTS.end - 1
        )))
    }
}

fn arm64_slot_offsets_for_access(slot: u8, access: HwBreakpointAccess) -> Result<(usize, usize)> {
    let slots = hwbp::arm64_slot_range(access);
    if slots.contains(&slot) {
        return arm64_slot_offsets(slot);
    }
    let kind = if matches!(access, HwBreakpointAccess::Execute) {
        "execute"
    } else {
        "watchpoint"
    };
    Err(Error::Kd(format!(
        "ARM64 {kind} slot {slot} is outside slots {}-{}",
        slots.start,
        slots.end - 1
    )))
}

fn thread_id_for(processor: u16) -> String {
    format!("p1.{:x}", u32::from(processor) + 1)
}

fn parse_thread_id(tid: &str) -> Result<u16> {
    let stripped = tid
        .strip_prefix("p1.")
        .ok_or_else(|| Error::Kd(format!("unrecognised thread id {tid}")))?;
    let idx =
        u16::from_str_radix(stripped, 16).map_err(|_| Error::Kd(format!("bad thread id {tid}")))?;
    if idx == 0 {
        return Err(Error::Kd(format!("thread id {tid} has zero index")));
    }
    Ok(idx - 1)
}

fn parse_thread_id_for_processor_count(tid: &str, processor_count: u16) -> Result<u16> {
    let processor = parse_thread_id(tid)?;
    if processor >= processor_count {
        return Err(Error::Kd(format!(
            "thread id {tid} selects processor {}, but guest reports {} processor(s)",
            processor + 1,
            processor_count
        )));
    }
    Ok(processor)
}

/// Whether the instruction at `pc` is the KD breakpoint instruction (`int3`
/// on AMD64, `BRK #0xF000` on ARM64), read through the target so it reflects
/// what will execute on resume.
///
/// An unreadable PC answers `false`. The only thing this answer is used for is
/// deciding whether to step the PC past a byte, and guessing wrong in that
/// direction costs a repeated stop, where guessing wrong in the other resumes
/// the guest inside an instruction.
pub fn breakpoint_instruction_at(
    framing: &mut KdFraming<KdTransport>,
    arch: Arch,
    processor: u16,
    pc: u64,
) -> bool {
    const INT3: [u8; 1] = [0xcc];
    const BRK_F000: [u8; 4] = 0xD43E_0000u32.to_le_bytes();
    let expected: &[u8] = match arch {
        Arch::Amd64 => &INT3,
        Arch::Arm64 => &BRK_F000,
    };
    match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
        api::read_virtual_memory(framing, processor, pc, expected.len() as u32)
    }) {
        Ok(bytes) => bytes == expected,
        Err(_) => false,
    }
}

/// Release every entry in the target's breakpoint table whose handle is in
/// neither `owned` nor `released`, reporting how many the target accepted and
/// adding those to `released`.
///
/// Handles are table indices plus one and only one debugger may be attached at
/// a time, so every handle we do not hold belongs to a session that is gone and
/// is ours to release. Releasing one restores the byte the entry displaced,
/// which is the only correct way to get a guest past an `int3` we cannot
/// account for. An empty slot refuses the handle. An entry whose page is not
/// resident (a breakpoint left in an unloaded driver) is accepted every time
/// but only marked expired: the kernel keeps it until the page returns, so a
/// released handle is never asked about again.
fn restore_unowned_breakpoint_handles(
    framing: &mut KdFraming<KdTransport>,
    processor: u16,
    owned: &HashSet<u32>,
    released: &mut HashSet<u32>,
) -> usize {
    let mut reclaimed = 0;
    for handle in 1..=KD_BREAKPOINT_TABLE_SIZE {
        if owned.contains(&handle) || released.contains(&handle) {
            continue;
        }
        match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        }) {
            Ok(()) => {
                kd_trace!("kd: reclaim: released handle {handle}");
                released.insert(handle);
                reclaimed += 1;
            }
            // An empty slot refuses the handle; that is the common answer.
            Err(Error::KdStatus { .. }) => {}
            // Transport trouble will resurface on whatever the caller does
            // next, with a better error than a reclaim failure could give.
            Err(error) => {
                kd_trace!("kd: reclaim: handle {handle} failed: {error}");
                break;
            }
        }
    }
    reclaimed
}

/// Word reclaimed table entries for the operator. A stranded entry is
/// invisible to them but costs a breakpoint slot for the rest of the boot.
fn reclaimed_breakpoints_notice(reclaimed: usize) -> Option<String> {
    (reclaimed != 0).then(|| {
        format!(
            "released {reclaimed} breakpoint table entr{} stranded by an earlier session",
            if reclaimed == 1 { "y" } else { "ies" }
        )
    })
}

/// Whether a stop seen during exit is a stray single-step: `STATUS_SINGLE_STEP`
/// away from any int3 we installed (and not a bugcheck). The backend-layer twin
/// of [`crate::session::stop_is_stray_single_step`]; `managed_bp_addresses` is
/// our installed-int3 set, standing in for the session's breakpoint manager.
fn exit_stop_is_stray_single_step(stop: &StopEvent, managed_bp_addresses: &HashSet<u64>) -> bool {
    stop.exception_code == Some(STATUS_SINGLE_STEP)
        && !stop.is_bugcheck
        && stop
            .program_counter
            .is_none_or(|pc| !managed_bp_addresses.contains(&pc))
}

fn append_control_registers_from_special(ctx: &mut Vec<u8>, special: &[u8]) -> Result<()> {
    if special.len() < KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }

    ctx.resize(context::REGISTER_BUFFER_SIZE, 0);

    let copy_reg = |ctx: &mut [u8], ctx_offset: usize, special_offset: usize| {
        ctx[ctx_offset..ctx_offset + 8]
            .copy_from_slice(&special[special_offset..special_offset + 8]);
    };
    copy_reg(ctx, context::OFFSET_CR0, KSPECIAL_REGISTERS_CR0_OFFSET);
    copy_reg(ctx, context::OFFSET_CR2, KSPECIAL_REGISTERS_CR2_OFFSET);
    copy_reg(ctx, context::OFFSET_CR3, KSPECIAL_REGISTERS_CR3_OFFSET);
    copy_reg(ctx, context::OFFSET_CR4, KSPECIAL_REGISTERS_CR4_OFFSET);
    copy_reg(ctx, context::OFFSET_DR0, KSPECIAL_REGISTERS_DR0_OFFSET);
    copy_reg(ctx, context::OFFSET_DR1, KSPECIAL_REGISTERS_DR1_OFFSET);
    copy_reg(ctx, context::OFFSET_DR2, KSPECIAL_REGISTERS_DR2_OFFSET);
    copy_reg(ctx, context::OFFSET_DR3, KSPECIAL_REGISTERS_DR3_OFFSET);
    copy_reg(ctx, context::OFFSET_DR6, KSPECIAL_REGISTERS_DR6_OFFSET);
    copy_reg(ctx, context::OFFSET_DR7, KSPECIAL_REGISTERS_DR7_OFFSET);
    copy_reg(ctx, context::OFFSET_CR8, KSPECIAL_REGISTERS_CR8_OFFSET);
    // KDESCRIPTOR layout is Pad[3] (6 bytes), Limit (2 bytes), Base (8
    // bytes). The register map stores each value in a synthetic 8-byte slot;
    // only the descriptor's meaningful bytes are copied for the limits.
    ctx[context::OFFSET_GDTR_LIMIT..context::OFFSET_GDTR_LIMIT + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_GDTR_OFFSET + 6..KSPECIAL_REGISTERS_GDTR_OFFSET + 8],
    );
    copy_reg(
        ctx,
        context::OFFSET_GDTR_BASE,
        KSPECIAL_REGISTERS_GDTR_OFFSET + 8,
    );
    ctx[context::OFFSET_IDTR_LIMIT..context::OFFSET_IDTR_LIMIT + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_IDTR_OFFSET + 6..KSPECIAL_REGISTERS_IDTR_OFFSET + 8],
    );
    copy_reg(
        ctx,
        context::OFFSET_IDTR_BASE,
        KSPECIAL_REGISTERS_IDTR_OFFSET + 8,
    );
    ctx[context::OFFSET_TR..context::OFFSET_TR + 2]
        .copy_from_slice(&special[KSPECIAL_REGISTERS_TR_OFFSET..KSPECIAL_REGISTERS_TR_OFFSET + 2]);
    ctx[context::OFFSET_LDTR..context::OFFSET_LDTR + 2].copy_from_slice(
        &special[KSPECIAL_REGISTERS_LDTR_OFFSET..KSPECIAL_REGISTERS_LDTR_OFFSET + 2],
    );
    Ok(())
}

fn update_special_debug_registers_from_context(special: &mut [u8], ctx: &[u8]) -> Result<()> {
    if special.len() < KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }
    context_payload(ctx)?;

    for (ctx_offset, special_offset) in [
        (context::OFFSET_DR0, KSPECIAL_REGISTERS_DR0_OFFSET),
        (context::OFFSET_DR1, KSPECIAL_REGISTERS_DR1_OFFSET),
        (context::OFFSET_DR2, KSPECIAL_REGISTERS_DR2_OFFSET),
        (context::OFFSET_DR3, KSPECIAL_REGISTERS_DR3_OFFSET),
        (context::OFFSET_DR6, KSPECIAL_REGISTERS_DR6_OFFSET),
        (context::OFFSET_DR7, KSPECIAL_REGISTERS_DR7_OFFSET),
    ] {
        special[special_offset..special_offset + 8]
            .copy_from_slice(&ctx[ctx_offset..ctx_offset + 8]);
    }
    Ok(())
}

fn update_arm64_debug_registers_from_context(special: &mut [u8], ctx: &[u8]) -> Result<()> {
    if special.len() < ARM64_KSPECIAL_REGISTERS_MIN_SIZE {
        return Err(Error::Kd(format!(
            "ARM64 KSPECIAL_REGISTERS buffer too short: {} bytes, expected at least {}",
            special.len(),
            ARM64_KSPECIAL_REGISTERS_MIN_SIZE
        )));
    }
    if ctx.len() < context_arm64::CONTEXT_SIZE {
        return Err(Error::Kd(format!(
            "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
            ctx.len(),
            context_arm64::CONTEXT_SIZE
        )));
    }
    copy_arm64_debug_registers(special, ctx, false);
    Ok(())
}

fn copy_arm64_debug_registers(dst: &mut [u8], src: &[u8], to_context: bool) {
    for &(special_base, context_base, width, count) in ARM64_DEBUG_REGISTER_OFFSETS {
        let (dst_base, src_base) = if to_context {
            (context_base, special_base)
        } else {
            (special_base, context_base)
        };
        for index in 0..count {
            let dst_offset = dst_base + index * width;
            let src_offset = src_base + index * width;
            dst[dst_offset..dst_offset + width]
                .copy_from_slice(&src[src_offset..src_offset + width]);
        }
    }
}

fn context_payload(data: &[u8]) -> Result<&[u8]> {
    if data.len() < context::CONTEXT_SIZE {
        return Err(Error::Kd(format!(
            "CONTEXT buffer too short: {} bytes, expected {}",
            data.len(),
            context::CONTEXT_SIZE
        )));
    }
    Ok(&data[..context::CONTEXT_SIZE])
}

fn stop_event(stop: StateChange) -> StopEvent {
    StopEvent {
        thread_id: Some(thread_id_for(stop.processor)),
        exception_code: (stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE)
            .then_some(stop.exception_code),
        first_chance: stop.exception_first_chance,
        exception_address: stop.exception_address,
        program_counter: Some(stop.program_counter),
        is_bugcheck: stop.is_bugcheck,
        bugcheck: stop.bugcheck,
        target_reloaded: stop.target_reloaded,
        target_kernel_base_hint: stop.kernel_base_hint,
        modules_changed: stop.new_state == DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
        assisted_breakin: stop.assisted_breakin,
    }
}

#[derive(Clone, Copy)]
struct DebugRegisterSlotState {
    address: u64,
    dr7: u64,
}

#[derive(Clone, Copy)]
struct Arm64DebugRegisterSlotState {
    address: u64,
    control: u32,
}

/// Who holds the transport, which is the same question as what the target
/// is doing: only a halted target answers requests, so the foreground holds
/// the framing exactly while it may issue them.
enum Link {
    /// Halted; the foreground issues requests.
    Halted(KdFraming<KdTransport>),
    /// Running, but only until a stop the foreground reads itself: a single
    /// step, or the resume on exit.
    RunningInline(KdFraming<KdTransport>),
    /// Running; the pump owns the framing, services the socket and reports
    /// the next stop.
    RunningPumped(PumpHandle),
    /// The pump thread panicked and the socket went with it.
    Lost,
}

impl Link {
    /// `running` explains the refusal while the pump owns the framing.
    fn framing(&mut self, running: &'static str) -> Result<&mut KdFraming<KdTransport>> {
        match self {
            Self::Halted(framing) | Self::RunningInline(framing) => Ok(framing),
            Self::RunningPumped(_) => Err(Error::TargetRunning(running)),
            Self::Lost => Err(Error::Kd(
                "KD transport lost: the servicing thread panicked".into(),
            )),
        }
    }

    fn is_running(&self) -> bool {
        matches!(self, Self::RunningInline(_) | Self::RunningPumped(_))
    }

    /// Take the pump handle, leaving the link lost until the framing comes
    /// back from the joined thread. Any other state is left untouched.
    fn take_pump(&mut self) -> Option<PumpHandle> {
        if !matches!(self, Self::RunningPumped(_)) {
            return None;
        }
        match std::mem::replace(self, Self::Lost) {
            Self::RunningPumped(pump) => Some(pump),
            _ => unreachable!("checked above"),
        }
    }

    /// Move to `running` (true) or halted (false) while the foreground keeps
    /// the framing; a pumped or lost link is left alone.
    fn set_inline_running(&mut self, running: bool) {
        let framing = match std::mem::replace(self, Self::Lost) {
            Self::Halted(framing) | Self::RunningInline(framing) => framing,
            other => {
                *self = other;
                return;
            }
        };
        *self = if running {
            Self::RunningInline(framing)
        } else {
            Self::Halted(framing)
        };
    }
}

/// Memory read through the target, remembered in `KD_VIRTUAL_LINE`-aligned
/// lines while it is halted. Nothing but this debugger changes guest memory
/// during a halt, so a line stays valid until the target runs or the
/// debugger writes. Virtual lines are keyed by the processor that resolved
/// them as well (user space follows that processor's root); page-table
/// lines by physical address.
struct LineCache<K> {
    lines: HashMap<K, Vec<u8>>,
}

impl<K: Eq + Hash> Default for LineCache<K> {
    fn default() -> Self {
        Self {
            lines: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash> LineCache<K> {
    fn get(&self, key: K) -> Option<&[u8]> {
        self.lines.get(&key).map(Vec::as_slice)
    }

    fn insert(&mut self, key: K, data: Vec<u8>) {
        if self.lines.len() >= LINE_CACHE_LIMIT {
            self.lines.clear();
        }
        self.lines.insert(key, data);
    }

    fn clear(&mut self) {
        self.lines.clear();
    }
}

pub struct KdBackend {
    link: Link,
    breakin_clone: KdTransport,
    backend_name: &'static str,
    register_map: RegisterMap,
    arch: Arch,
    /// Kernel page-table root, first read from the target at attach and
    /// later confirmed by the session; on ARM64 it fills the synthetic `cr3`
    /// register slot.
    kernel_dtb_override: u64,
    processor_count: u16,
    current_processor: u16,
    last_stop_processor: u16,
    last_exception_code: u32,
    last_rip: u64,
    reconnect_assist_after_continue: Option<Duration>,
    bp_handles: HashMap<u64, u32>,
    managed_bp_addresses: HashSet<u64>,
    breakin_addresses: HashSet<u64>,
    pending_write_breakpoint: Option<PendingWriteBreakpoint>,
    special_register_cache: HashMap<u16, Vec<u8>>,
    /// Per-processor `CONTEXT` for the current halt. See [`Self::read_registers`].
    context_cache: HashMap<u16, Vec<u8>>,
    /// Avoid repeated round trips or timeouts after an ARM64 control-space read fails.
    special_registers_unsupported: bool,
    efer_cache: HashMap<u16, u64>,
    /// Virtual memory read through the target for the current halt; see
    /// [`Self::read_virtual_bytes`].
    virtual_lines: LineCache<(u16, u64)>,
    /// Page-table entries read for the host page walk this halt; see
    /// [`Self::read_page_table_bytes`].
    table_lines: LineCache<u64>,
    /// Most bytes one virtual-read fill asks for: a chunk, until a reply
    /// comes back shorter than asked (a KDNET datagram carries 0x448), after
    /// which fills stay within what the transport returns.
    virtual_fill_cap: usize,
    /// Set after an explicit frontend cleanup. Prevents `Drop` from overriding
    /// a deliberate halted exit after breakpoint restoration failed.
    exit_prepared: bool,
    /// Captured guest debug output (DbgPrint). Shared with the background pump,
    /// which is the sole socket reader (and so the primary capture point) while
    /// the VM runs.
    debug_log: DebugLog,
    /// Page translations valid while the target is halted; shared with
    /// [`KdMemory`] and cleared on every resume and every write.
    translations: Arc<TranslationCache>,
    /// Operator-facing diagnostics raised mid-operation, drained by the
    /// session through [`DebugBackend::take_notices`].
    notices: Vec<String>,
    /// Table handles reclaimed from dead sessions; see
    /// [`restore_unowned_breakpoint_handles`].
    released_handles: HashSet<u32>,
    /// Why a request cannot be served while the target runs, for the error
    /// a running target answers with; see [`Self::note_host_memory_unavailable`].
    running_reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdMemorySource {
    Auto,
    Host,
    Kd,
}

impl FromStr for KdMemorySource {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "host" => Ok(Self::Host),
            "kd" => Ok(Self::Kd),
            other => Err(format!(
                "unknown memory source '{other}': expected auto, host, or kd"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KdTargetHints {
    pub kernel_dtb: Dtb,
    pub kernel_base: VirtAddr,
    pub ps_loaded_module_list: VirtAddr,
    pub arch: Arch,
}

/// Shared KD transport used by the debugger facade and remote physical memory.
///
/// Every operation locks the same `KdBackend`, preserving KD packet ordering.
#[derive(Clone)]
pub struct KdMemory {
    inner: Arc<Mutex<KdBackend>>,
    translations: Arc<TranslationCache>,
}

pub struct KdBackendHandle {
    inner: Arc<Mutex<KdBackend>>,
    register_map: RegisterMap,
    backend_name: &'static str,
}

impl KdBackendHandle {
    fn lock(&self) -> MutexGuard<'_, KdBackend> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl KdMemory {
    fn lock(&self) -> MutexGuard<'_, KdBackend> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl MemoryOps<PhysAddr> for KdMemory {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.lock().read_physical_bytes(addr, buf)
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.lock().write_physical_bytes(addr, buf)
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        self.lock().read_virtual_direct(addr, root, buf)
    }

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        self.lock().write_virtual_direct(addr, root, buf)
    }

    fn can_mediate_writes(&self) -> bool {
        !self.lock().link.is_running()
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        Some(&self.translations)
    }

    fn read_page_table_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.lock().read_page_table_bytes(addr, buf)
    }
}

impl KdBackend {
    /// Connect to a KDCOM serial pipe and stop at the initial state-change.
    /// Connect to a KDCOM serial pipe and stop at the initial state-change.
    /// Connection progress (the wait for a target can run for a minute) is
    /// reported one line at a time through `progress`.
    pub fn connect(socket_path: &str, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        progress(&format!("kd: using KDCOM backend on {socket_path}"));
        let stream = UnixStream::connect(socket_path)
            .map_err(|err| kd_socket_connect_error(socket_path, err))?;
        Self::connect_transport(
            KdTransport::Serial(stream),
            "kd: serial connected; waiting for Windows KD target",
            "kd",
            progress,
        )
    }

    /// Listen for a KDNET target and stop at the initial state-change.
    pub fn connect_net(
        listen_addr: &str,
        key: &str,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        progress(&format!("kdnet: listening on {listen_addr}"));
        let stream = KdNetStream::bind(listen_addr, key)?;
        Self::connect_transport(
            KdTransport::Network(stream),
            "kdnet: listener ready; waiting for Windows KDNET target",
            "kdnet",
            progress,
        )
    }

    fn connect_transport(
        transport: KdTransport,
        waiting_message: &str,
        backend_name: &'static str,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        let network_generation = transport.network_session_generation();
        let mut framing = KdFraming::new(transport);
        if let Some(generation) = network_generation {
            framing.use_kdnet_packet_ids(generation);
        }
        let initial_timeout = kd_initial_timeout()?;

        progress(&format!(
            "{waiting_message} (timeout {}s)",
            initial_timeout.as_secs()
        ));

        // A waiting kernel retransmits state-change; otherwise break in.
        let mut initial_stop = poll_for_initial_break(&mut framing, initial_timeout, progress)?;
        let version = match probe_initial_request(&mut framing, initial_stop.processor) {
            Ok(version) => version,
            Err(err) => {
                if !is_initial_resync_error(&err) {
                    return Err(err);
                }
                kd_trace!("kd: initial request probe failed ({err}); resetting KD packet stream");
                framing.send_reset()?;
                initial_stop = poll_for_initial_break(&mut framing, initial_timeout, progress)?;
                probe_initial_request(&mut framing, initial_stop.processor)?
            }
        };
        let arch = detect_arch(version.machine_type)?;
        let register_map = match arch {
            Arch::Amd64 => context::build_register_map(),
            Arch::Arm64 => context_arm64::build_register_map(),
        };
        // The first state-change often arrives with KD's SYNC bit set. That is
        // the baseline connection, not a target reload for the REPL to surface.
        framing.take_peer_reset_seen();
        kd_trace!(
            "kd: initial state-change received: p{}/{}, exc={:#x}, rip={:#x}",
            initial_stop.processor + 1,
            initial_stop.number_processors,
            initial_stop.exception_code,
            initial_stop.program_counter
        );

        // A second handle on the same transport lets the foreground send an
        // unframed break-in byte while the pump owns `framing` for reading.
        let breakin_clone = framing.transport_mut().try_clone()?;

        // Only one debugger is attached at a time, so every entry already in
        // the target's breakpoint table was left by a session that is gone:
        // its `int3` is still displacing a byte of guest code and its slot is
        // held until the guest reboots. Release them before anything reads
        // guest memory or resumes, so no later decision has to reason about an
        // `int3` nobody can account for.
        let mut released_handles = HashSet::new();
        if let Some(notice) = reclaimed_breakpoints_notice(restore_unowned_breakpoint_handles(
            &mut framing,
            initial_stop.processor,
            &HashSet::new(),
            &mut released_handles,
        )) {
            progress(&notice);
        }

        // A target left waiting on a debugger that died mid-breakpoint reports
        // its stop again to us, at the breakpoint's address. The kernel has
        // dropped that table entry and its `int3` by the time the RESET
        // handshake completes, so the byte at PC tells the two cases apart: a
        // hard-coded break (`cc`, a break-in site to remember) or a stale
        // breakpoint hit (resume in place; never treat that address as a
        // break-in, or later real hits there would be absorbed as noise).
        let mut stopped_on_stale_breakpoint = false;
        if initial_stop.exception_code == STATUS_BREAKPOINT {
            stopped_on_stale_breakpoint = !breakpoint_instruction_at(
                &mut framing,
                arch,
                initial_stop.processor,
                initial_stop.program_counter,
            );
            if stopped_on_stale_breakpoint {
                kd_trace!(
                    "kd: initial stop at {:#x} was a stale breakpoint; resuming in place",
                    initial_stop.program_counter
                );
            }
        }

        let mut breakin_addresses = HashSet::new();
        if initial_stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE
            && initial_stop.exception_code == STATUS_BREAKPOINT
            && !stopped_on_stale_breakpoint
        {
            breakin_addresses.insert(initial_stop.program_counter);
        }

        Ok(Self {
            link: Link::Halted(framing),
            breakin_clone,
            backend_name,
            register_map,
            arch,
            kernel_dtb_override: 0,
            processor_count: initial_stop.number_processors.max(1),
            current_processor: initial_stop.processor,
            last_stop_processor: initial_stop.processor,
            last_exception_code: initial_stop.exception_code,
            last_rip: initial_stop.program_counter,
            bp_handles: HashMap::new(),
            managed_bp_addresses: HashSet::new(),
            breakin_addresses,
            pending_write_breakpoint: None,
            reconnect_assist_after_continue: None,
            special_register_cache: HashMap::new(),
            context_cache: HashMap::new(),
            special_registers_unsupported: false,
            efer_cache: HashMap::new(),
            virtual_lines: LineCache::default(),
            table_lines: LineCache::default(),
            virtual_fill_cap: KD_REMOTE_MEMORY_CHUNK,
            exit_prepared: false,
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            translations: Arc::new(TranslationCache::default()),
            notices: Vec::new(),
            released_handles,
            running_reason: MEMORY_OVER_KD_CHOSEN,
        })
    }

    /// Foreground access to the framing. Errors if the pump currently owns it
    /// (i.e. the VM is running) or if a WriteBreakpoint reply is still pending;
    /// issuing another request in either state would steal the outstanding reply
    /// and desync the packet stream. Request/reply only happens while stopped
    fn framing(&mut self) -> Result<&mut KdFraming<KdTransport>> {
        self.require_no_pending_write_breakpoint()?;
        self.framing_unchecked()
    }

    /// Framing access without the pending-write-breakpoint guard. Only the
    /// breakpoint completion path may use this, since it exists precisely to
    /// drain that outstanding reply
    fn framing_unchecked(&mut self) -> Result<&mut KdFraming<KdTransport>> {
        self.link.framing(self.running_reason)
    }

    /// Record that `--memory-source auto` fell back to KD memory, so the
    /// refusal a running target answers with does not suggest a setting the
    /// operator is already on.
    pub fn note_host_memory_unavailable(&mut self) {
        self.running_reason = MEMORY_OVER_KD_FALLBACK;
    }

    /// Hand the framing to a freshly spawned background pump. The target has
    /// just been resumed (see [`record_running`]), so the link is inline.
    fn start_pump(
        &mut self,
        reconnect_assist_delay: Option<Duration>,
        drain: Option<ContinueDrain>,
    ) -> Result<()> {
        let framing = match std::mem::replace(&mut self.link, Link::Lost) {
            Link::RunningInline(framing) => framing,
            other => {
                self.link = other;
                return Err(Error::Kd(
                    "cannot start KD pump: target is not resuming".into(),
                ));
            }
        };
        let (stop_tx, stop_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let pump_shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::new(AtomicBool::new(false));
        let pump_reported_stop = Arc::clone(&reported_stop);
        let pump_debug_log = self.debug_log.clone();
        let arch = self.arch;
        let breakin_requested = drain
            .as_ref()
            .map(ContinueDrain::interrupt_flag)
            .unwrap_or_default();
        let join = spawn(move || {
            run_pump(
                framing,
                arch,
                PumpLink {
                    stop_tx,
                    shutdown: pump_shutdown,
                    reported_stop: pump_reported_stop,
                },
                reconnect_assist_delay,
                pump_debug_log,
                drain,
            )
        });
        kd_trace!("kd: pump: spawned background servicing thread");
        self.link = Link::RunningPumped(PumpHandle {
            join,
            stop_rx,
            shutdown,
            reported_stop,
            breakin_requested,
        });
        Ok(())
    }

    /// Join the pump thread and take back ownership of the framing
    fn reclaim_framing(&mut self) {
        if let Some(pump) = self.link.take_pump() {
            match pump.join.join() {
                // Whoever asked for the framing back also consumes the stop,
                // if there was one, and records it; until then the target is
                // still running.
                Ok(framing) => self.link = Link::RunningInline(framing),
                Err(_) => {
                    // The pump panicked; the framing (and socket) is lost. The
                    // next foreground op surfaces this as a transport error
                    kd_trace!("kd: pump: thread panicked, framing lost");
                }
            }
        }
    }

    /// Wait for the pump to report a stop. `wait` bounds a non-blocking poll;
    /// `None` blocks until the pump produces a stop. On a stop (or pump error)
    /// the framing is reclaimed and the pump handle dropped
    fn take_pump_stop(&mut self, wait: Option<Duration>) -> Result<Option<StateChange>> {
        let Link::RunningPumped(pump) = &self.link else {
            return Ok(None);
        };
        let received = match wait {
            None => pump
                .stop_rx
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
            Some(timeout) => pump.stop_rx.recv_timeout(timeout),
        };
        match received {
            Ok(result) => {
                self.reclaim_framing();
                result.map(Some).map_err(Error::Kd)
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.reclaim_framing();
                Err(Error::Kd("KD pump exited without reporting a stop".into()))
            }
        }
    }

    /// Stop the pump (if running) without waiting for a stop event, reclaiming
    /// the framing. Used on teardown and when abandoning an interrupt
    fn shutdown_pump(&mut self) {
        let _ = self.shutdown_pump_with_stop();
    }

    fn try_recv_pump_stop(
        stop_rx: &mpsc::Receiver<std::result::Result<StateChange, String>>,
    ) -> Result<Option<StateChange>> {
        match stop_rx.try_recv() {
            Ok(Ok(stop)) => Ok(Some(stop)),
            Ok(Err(message)) => Err(Error::Kd(message)),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    /// Stop the pump and return a stop it reported during shutdown, if any.
    fn shutdown_pump_with_stop(&mut self) -> Result<Option<StateChange>> {
        let Some(pump) = self.link.take_pump() else {
            return Ok(None);
        };
        let PumpHandle {
            join,
            stop_rx,
            shutdown,
            reported_stop: _,
            breakin_requested: _,
        } = pump;
        shutdown.store(true, Ordering::SeqCst);
        let stop = Self::try_recv_pump_stop(&stop_rx)?;
        match join.join() {
            Ok(framing) => self.link = Link::RunningInline(framing),
            Err(_) => {
                kd_trace!("kd: pump: thread panicked during shutdown, framing lost");
                if stop.is_none() {
                    return Err(Error::Kd("KD pump thread panicked during shutdown".into()));
                }
            }
        }
        if stop.is_some() {
            return Ok(stop);
        }
        Self::try_recv_pump_stop(&stop_rx)
    }

    /// Send an unframed break-in byte over the cloned socket fd. Safe to call
    /// while the pump owns the framing for reading
    fn send_raw_breakin(&mut self) -> Result<()> {
        self.breakin_clone.write_all(&[BREAKIN_BYTE])?;
        self.breakin_clone.flush()?;
        Ok(())
    }

    fn known_breakin_stop(&self, stop: &StateChange) -> bool {
        stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE
            && stop.exception_code == STATUS_BREAKPOINT
            && self.breakin_addresses.contains(&stop.program_counter)
            && !self.managed_bp_addresses.contains(&stop.program_counter)
    }

    fn mark_known_breakin_stop(&self, mut stop: StateChange) -> StateChange {
        if self.known_breakin_stop(&stop) {
            stop.assisted_breakin = true;
        }
        stop
    }

    fn pending_write_breakpoint_error(pending: PendingWriteBreakpoint) -> Error {
        Error::Kd(format!(
            "breakpoint install at {:#x} is pending; retry the same bp command before issuing other KD commands",
            pending.addr
        ))
    }

    fn require_no_pending_write_breakpoint(&self) -> Result<()> {
        match self.pending_write_breakpoint {
            Some(pending) => Err(Self::pending_write_breakpoint_error(pending)),
            None => Ok(()),
        }
    }

    fn complete_pending_write_breakpoint(&mut self, addr: u64) -> Result<bool> {
        let Some(pending) = self.pending_write_breakpoint else {
            return Ok(false);
        };
        if pending.addr != addr {
            return Err(Self::pending_write_breakpoint_error(pending));
        }

        kd_trace!(
            "kd: breakpoint: waiting for late WriteBreakPoint reply at {:#x}",
            pending.addr
        );
        let result = with_framing_read_timeout_raw(
            self.framing_unchecked()?,
            KD_REQUEST_TIMEOUT,
            |framing| api::recv_write_breakpoint_reply(framing, pending.processor),
        );
        match result {
            Ok(handle) => {
                kd_trace!(
                    "kd: breakpoint: completed late WriteBreakPoint at {:#x} handle={}",
                    pending.addr,
                    handle
                );
                self.pending_write_breakpoint = None;
                self.bp_handles.insert(pending.addr, handle);
                self.managed_bp_addresses.insert(pending.addr);
                Ok(true)
            }
            Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => Err(Error::Kd(format!(
                "KD request timed out after {}s; breakpoint install is still pending",
                KD_REQUEST_TIMEOUT.as_secs()
            ))),
            Err(err) => {
                self.pending_write_breakpoint = None;
                Err(err)
            }
        }
    }

    fn record_stop(&mut self, stop: &StateChange) {
        if stop.target_reloaded {
            kd_trace!("kd: target reload detected; clearing target-owned breakpoint state");
            self.bp_handles.clear();
            self.managed_bp_addresses.clear();
            self.breakin_addresses.clear();
            self.pending_write_breakpoint = None;
        } else if stop.is_bugcheck {
            self.reconnect_assist_after_continue = Some(POST_BUGCHECK_RECONNECT_ASSIST_DELAY);
        }
        let managed_breakpoint_stop = stop.exception_code == STATUS_BREAKPOINT
            && self.managed_bp_addresses.contains(&stop.program_counter);
        if stop.assisted_breakin
            && stop.exception_code == STATUS_BREAKPOINT
            && !managed_breakpoint_stop
        {
            self.breakin_addresses.insert(stop.program_counter);
        }
        kd_trace!(
            "kd: stop on p{}, new_state={:#x}, exception_code={:#x}, rip={:#x}, managed_bp={}",
            stop.processor + 1,
            stop.new_state,
            stop.exception_code,
            stop.program_counter,
            managed_breakpoint_stop
        );
        self.current_processor = stop.processor;
        // A rebooted target reports its real count; between reboots the count
        // never shrinks (no hot-unplug), so keep the high-water mark.
        self.processor_count = if stop.target_reloaded {
            stop.number_processors.max(1)
        } else {
            self.processor_count.max(stop.number_processors.max(1))
        };
        self.last_stop_processor = stop.processor;
        self.last_exception_code = stop.exception_code;
        self.last_rip = stop.program_counter;
        self.special_register_cache.clear();
        self.context_cache.clear();
        self.efer_cache.clear();
        self.link.set_inline_running(false);
    }

    fn record_running(&mut self) {
        self.link.set_inline_running(true);
        self.special_register_cache.clear();
        self.context_cache.clear();
        self.efer_cache.clear();
        self.virtual_lines.clear();
        self.table_lines.clear();
        self.translations.resume();
    }

    fn context_flags(&self) -> u32 {
        match self.arch {
            Arch::Amd64 => context::CONTEXT_ALL,
            Arch::Arm64 => context_arm64::CONTEXT_ALL,
        }
    }

    /// Step the resume PC past a hard-coded `int3`, when that is genuinely what
    /// is at the PC.
    ///
    /// An `int3` that is really part of the guest's code has already executed
    /// by the time the kernel reports the stop with the PC back on it, so
    /// resuming in place would trap on it forever and the PC has to move past
    /// it. Every other `int3` at a stop PC is a *displaced* byte standing in
    /// for a real instruction, and moving the PC past one of those resumes
    /// inside that instruction: `48 8b c4` (`mov rax,rsp`) entered at its
    /// second byte is `8b c4` (`mov eax,esp`), which truncates the register the
    /// next instruction dereferences, and the guest faults three bytes into the
    /// function it was entering. So a displaced byte is never stepped over:
    ///
    /// * One of ours is left alone; the host's step-over owns removing and
    ///   restoring it.
    /// * A table entry a dead session stranded is released, which makes the
    ///   target restore the byte it displaced. Attach clears the table, but a
    ///   target reload drops our handles while the entries survive.
    /// * A PC that cannot be read resumes in place. Failing that way costs a
    ///   repeated stop; failing the other way corrupts the guest.
    ///
    /// The PC is read from the target rather than from the recorded stop: hosts
    /// rewind and rewrite it between a stop and the resume, so only the target
    /// knows what is about to execute.
    fn skip_hardcoded_breakpoint(&mut self, processor: u16) -> Result<()> {
        if self.last_exception_code != STATUS_BREAKPOINT {
            return Ok(());
        }
        self.require_no_pending_write_breakpoint()?;
        let arch = self.arch;
        let register_map = self.register_map.clone();
        let pc = read_program_counter(
            self.link.framing(self.running_reason)?,
            &register_map,
            arch,
            processor,
        )?;
        if self.managed_bp_addresses.contains(&pc) {
            return Ok(());
        }
        if !breakpoint_instruction_at(self.link.framing(self.running_reason)?, arch, processor, pc)
        {
            kd_trace!(
                "kd: stop at {pc:#x} reported a breakpoint but memory holds none; resuming in place"
            );
            return Ok(());
        }

        let owned: HashSet<u32> = self.bp_handles.values().copied().collect();
        let reclaimed = restore_unowned_breakpoint_handles(
            self.link.framing(self.running_reason)?,
            processor,
            &owned,
            &mut self.released_handles,
        );
        self.notices.extend(reclaimed_breakpoints_notice(reclaimed));
        if reclaimed != 0
            && !breakpoint_instruction_at(
                self.link.framing(self.running_reason)?,
                arch,
                processor,
                pc,
            )
        {
            kd_trace!("kd: released a stranded breakpoint at {pc:#x}; resuming in place");
            return Ok(());
        }

        kd_trace!(
            "kd: advancing p{} past a hard-coded int3 at {pc:#x}",
            processor + 1
        );
        // The PC goes straight through the context API, behind
        // `write_registers` and its cache invalidation.
        self.context_cache.remove(&processor);
        advance_pc_past_breakpoint(
            self.link.framing(self.running_reason)?,
            &register_map,
            arch,
            processor,
            pc,
        )
    }

    fn read_dr_slot_state(&mut self, slot: u8) -> Result<DebugRegisterSlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        Ok(DebugRegisterSlotState {
            address: wire::read_u64(&special, Self::kspecial_dr_offset(slot)),
            dr7: wire::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET),
        })
    }

    fn apply_dr_restore(&mut self, slot: u8, state: DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        wire::write_u64(&mut special, Self::kspecial_dr_offset(slot), state.address);
        wire::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, state.dr7);
        self.write_special_registers(special)
    }

    fn read_arm64_slot_state(&mut self, slot: u8) -> Result<Arm64DebugRegisterSlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        Ok(Arm64DebugRegisterSlotState {
            address: wire::read_u64(&special, address_offset),
            control: wire::read_u32(&special, control_offset),
        })
    }

    fn apply_arm64_restore(&mut self, slot: u8, state: Arm64DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        wire::write_u64(&mut special, address_offset, state.address);
        wire::write_u32(&mut special, control_offset, state.control);
        self.write_special_registers(special)
    }

    fn rollback_slot_states<S: Copy>(
        &mut self,
        slot: u8,
        states: &[(u16, S)],
        mut restore: impl FnMut(&mut Self, u8, S) -> Result<()>,
    ) -> Result<()> {
        let mut first_error = None;
        for &(processor, state) in states.iter().rev() {
            self.current_processor = processor;
            if let Err(error) = restore(self, slot, state)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Apply one hardware-slot update to every processor as a transaction.
    /// Each processor's prior slot state is captured before its write; a
    /// failure restores every processor that may have been modified.
    fn update_slot_on_all_processors<S: Copy>(
        &mut self,
        slot: u8,
        operation: &str,
        label: &str,
        mut read: impl FnMut(&mut Self, u8) -> Result<S>,
        mut restore: impl FnMut(&mut Self, u8, S) -> Result<()>,
        mut update: impl FnMut(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let slot_count = self.hardware_breakpoint_slots();
        if slot >= slot_count {
            return Err(Error::Kd(format!(
                "invalid hardware breakpoint slot {slot} (expected 0-{})",
                slot_count.saturating_sub(1)
            )));
        }
        let saved = self.current_processor;
        let result = (|| {
            let mut applied = Vec::with_capacity(self.processor_count.max(1) as usize);
            let mut failure = None;

            for processor in 0..self.processor_count.max(1) {
                self.current_processor = processor;
                let previous = match read(self, slot) {
                    Ok(previous) => previous,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                };
                applied.push((processor, previous));
                if let Err(error) = update(self) {
                    failure = Some(error);
                    break;
                }
            }

            let Some(error) = failure else {
                return Ok(());
            };
            match self.rollback_slot_states(slot, &applied, &mut restore) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(Error::Kd(format!(
                    "{label} {operation} failed: {error}; rollback also failed: {rollback_error}"
                ))),
            }
        })();
        self.current_processor = saved;
        result
    }

    fn apply_arm64_set(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let (address_offset, control_offset) = arm64_slot_offsets_for_access(slot, access)?;
        if matches!(access, HwBreakpointAccess::Execute) && (len != 1 || !addr.is_multiple_of(4)) {
            return Err(Error::InvalidArgument(
                "ARM64 execute hardware breakpoints require a 4-byte-aligned address and length 1"
                    .into(),
            ));
        }

        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        if matches!(access, HwBreakpointAccess::Execute) {
            wire::write_u64(&mut special, address_offset, addr);
            wire::write_u32(&mut special, control_offset, hwbp::arm64_bcr_value(addr));
        } else {
            wire::write_u64(&mut special, address_offset, hwbp::arm64_wvr_address(addr));
            wire::write_u32(
                &mut special,
                control_offset,
                hwbp::arm64_wcr_value(addr, access, len),
            );
        }
        self.write_special_registers(special)
    }

    fn apply_arm64_clear(&mut self, slot: u8) -> Result<()> {
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        wire::write_u64(&mut special, address_offset, 0);
        wire::write_u32(&mut special, control_offset, 0);
        self.write_special_registers(special)
    }

    fn kspecial_dr_offset(slot: u8) -> usize {
        KSPECIAL_REGISTERS_DR0_OFFSET + slot as usize * 8
    }

    /// Program the currently selected processor's kernel debug-register state
    /// to trap on `access` at `addr` (`len` bytes) via slot `slot`.
    fn apply_dr_set(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        wire::write_u64(&mut special, Self::kspecial_dr_offset(slot), addr);
        let dr7 = wire::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET);
        let dr7 = hwbp::dr7_set_slot(dr7, slot, access, len);
        wire::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, dr7);
        self.write_special_registers(special)
    }

    /// Disable slot `slot` on the currently selected processor and zero its
    /// address register.
    fn apply_dr_clear(&mut self, slot: u8) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let dr7 = wire::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET);
        let dr7 = hwbp::dr7_clear_slot(dr7, slot);
        wire::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, dr7);
        wire::write_u64(&mut special, Self::kspecial_dr_offset(slot), 0);
        self.write_special_registers(special)
    }

    fn read_special_registers_uncached(&mut self, processor: u16) -> Result<Vec<u8>> {
        let (base, size) = kspecial_control_space(self.arch);
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_control_space(framing, processor, base, size as u32)
        })
    }

    fn read_msr_value(&mut self, processor: u16, msr: u32) -> Result<u64> {
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_machine_specific_register(framing, processor, msr)
        })
    }

    fn validate_processor(&self, processor: u16) -> Result<()> {
        if processor >= self.processor_count.max(1) {
            return Err(Error::Kd(format!(
                "processor {} is out of range (target reports {} processor(s))",
                processor + 1,
                self.processor_count.max(1)
            )));
        }
        Ok(())
    }

    fn write_special_registers(&mut self, special: Vec<u8>) -> Result<()> {
        let processor = self.current_processor;
        let (base, expected_size) = kspecial_control_space(self.arch);
        let actual = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_control_space(framing, processor, base, &special)
        })?;
        if actual as usize != special.len() {
            return Err(Error::Kd(format!(
                "short KSPECIAL_REGISTERS write on processor {}: wrote {} of {} bytes (requested layout size {})",
                processor + 1,
                actual,
                special.len(),
                expected_size,
            )));
        }
        self.special_register_cache.insert(processor, special);
        Ok(())
    }

    fn read_special_registers(&mut self) -> Result<&[u8]> {
        if !self
            .special_register_cache
            .contains_key(&self.current_processor)
        {
            let processor = self.current_processor;
            let data = self.read_special_registers_uncached(processor)?;
            self.special_register_cache.insert(processor, data);
        }

        self.special_register_cache
            .get(&self.current_processor)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::Kd("special-register cache lookup failed".into()))
    }

    /// Prefer the kernel debug-register copies; fall back to GetContext if unavailable.
    fn arm64_special_registers(&mut self) -> Option<&[u8]> {
        if self.special_registers_unsupported {
            return None;
        }
        if let Err(error) = self.read_special_registers().map(|_| ()) {
            kd_trace!("kd: ARM64 KSPECIAL_REGISTERS unavailable: {error}");
            self.special_registers_unsupported = true;
            return None;
        }
        self.special_register_cache
            .get(&self.current_processor)
            .map(Vec::as_slice)
            .filter(|special| special.len() >= ARM64_KSPECIAL_REGISTERS_MIN_SIZE)
    }

    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        match self.arch {
            Arch::Amd64 => {
                let special = self.read_special_registers()?;
                append_control_registers_from_special(ctx, special)
            }
            Arch::Arm64 => {
                if ctx.len() < context_arm64::CONTEXT_SIZE {
                    return Err(Error::Kd(format!(
                        "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
                        ctx.len(),
                        context_arm64::CONTEXT_SIZE
                    )));
                }
                let ttbr0 =
                    match self.read_msr_value(self.current_processor, ARM64_WINDBG_TTBR0_EL1) {
                        Ok(value) => value & Arch::Arm64.dtb_page_mask(),
                        Err(error) => {
                            kd_trace!("kd: ARM64 TTBR0_EL1 read unavailable: {error}");
                            0
                        }
                    };
                let (esr, far) = if self.last_exception_code == STATUS_SINGLE_STEP {
                    let esr =
                        match self.read_msr_value(self.current_processor, ARM64_WINDBG_ESR_EL1) {
                            Ok(value) => value,
                            Err(error) => {
                                kd_trace!("kd: ARM64 ESR_EL1 read unavailable: {error}");
                                0
                            }
                        };
                    let far =
                        match self.read_msr_value(self.current_processor, ARM64_WINDBG_FAR_EL1) {
                            Ok(value) => value,
                            Err(error) => {
                                kd_trace!("kd: ARM64 FAR_EL1 read unavailable: {error}");
                                0
                            }
                        };
                    (esr, far)
                } else {
                    (0, 0)
                };
                let kernel_dtb = self.kernel_dtb_override;
                ctx.resize(context_arm64::REGISTER_BUFFER_SIZE, 0);
                ctx[context_arm64::OFFSET_CR3..context_arm64::OFFSET_CR3 + 8]
                    .copy_from_slice(&kernel_dtb.to_le_bytes());
                ctx[context_arm64::OFFSET_TTBR0..context_arm64::OFFSET_TTBR0 + 8]
                    .copy_from_slice(&ttbr0.to_le_bytes());
                if let Some(special) = self.arm64_special_registers() {
                    copy_arm64_debug_registers(ctx, special, true);
                }
                if self.last_exception_code == STATUS_SINGLE_STEP {
                    ctx[context_arm64::OFFSET_ESR..context_arm64::OFFSET_ESR + 8]
                        .copy_from_slice(&esr.to_le_bytes());
                    ctx[context_arm64::OFFSET_FAR..context_arm64::OFFSET_FAR + 8]
                        .copy_from_slice(&far.to_le_bytes());
                }
                Ok(())
            }
        }
    }

    fn continue_preserving_dr7(&mut self, processor: u16, status: u32, trace: bool) -> Result<()> {
        match self.arch {
            Arch::Amd64 => {
                if !self.special_register_cache.contains_key(&processor) {
                    let special = self.read_special_registers_uncached(processor)?;
                    self.special_register_cache.insert(processor, special);
                }
                let special = self
                    .special_register_cache
                    .get(&processor)
                    .expect("cache holds processor; we just inserted it on miss");
                let dr7 = wire::read_u64(special, KSPECIAL_REGISTERS_DR7_OFFSET);
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::continue_api2(framing, processor, status, trace, dr7)
                })
            }
            Arch::Arm64 => {
                // ARM64_DBGKD_CONTROL_SET has no Dr7 field; the kernel
                // single-steps via MDSCR when TraceFlag is set.
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::continue_api2_arm64(framing, processor, status, trace)
                })
            }
        }
    }

    fn continue_stopped_for_exit(&mut self) -> Result<()> {
        let processor = self.last_stop_processor;
        self.skip_hardcoded_breakpoint(processor)?;
        self.continue_preserving_dr7(processor, api::DBG_CONTINUE, false)?;
        self.record_running();
        Ok(())
    }

    /// Hand every breakpoint site the host did not clear back to the target.
    ///
    /// A host that exits through its own teardown removes breakpoints through
    /// the manager and leaves nothing here. Abnormal exits (a termination
    /// signal, an I/O error unwinding past the REPL's cleanup) skip that path,
    /// and what is left behind is not just an `int3` in guest code: each site
    /// also holds one of the 32 entries in the target's `KdpBreakpointTable`
    /// for the rest of the boot, because only the debugger that owns a handle
    /// can release it. Best effort by construction: this runs while the
    /// process is already going away.
    fn restore_tracked_breakpoints(&mut self) {
        // Requests are only answered while the target is halted, and a pending
        // install owns the next reply on the wire.
        if self.bp_handles.is_empty()
            || self.link.is_running()
            || self.pending_write_breakpoint.is_some()
        {
            return;
        }
        let processor = self.current_processor;
        self.virtual_lines.clear();
        for (addr, handle) in take(&mut self.bp_handles) {
            let Ok(framing) = self.framing() else { return };
            match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
                api::restore_breakpoint(framing, processor, handle)
            }) {
                Ok(()) => {
                    self.managed_bp_addresses.remove(&addr);
                }
                // The transport is going away with the process; a stranded
                // entry is better than blocking teardown on a retry.
                Err(error) => kd_trace!(
                    "kd: exit: restoring breakpoint handle {handle} at {addr:#x} failed: {error}"
                ),
            }
        }
    }

    /// Reclaim breakpoint slots stranded by an earlier debugger session, then
    /// retry the install once.
    ///
    /// `KdpAddBreakpoint` answers `STATUS_UNSUCCESSFUL` in exactly two cases a
    /// debugger can hit: the address already has an entry in the target's
    /// 32-slot `KdpBreakpointTable`, or every slot is taken. Both mean the same
    /// thing in practice, because only the debugger holding a handle can
    /// release one and a session killed mid-flight takes its handles with it -
    /// so a fresh session can be locked out of an address it never touched,
    /// until the guest reboots.
    ///
    /// Handles are table indices plus one and only one debugger may be attached
    /// at a time, so every handle we do not own belongs to a dead session and is
    /// ours to release. Releasing one cannot corrupt the guest: before writing
    /// an entry's saved byte back, `KdpLowWriteContent` checks the site still
    /// holds the breakpoint instruction. When that write-back cannot happen,
    /// as for a breakpoint in a driver's discarded `INIT` section, the target
    /// reports success but keeps the entry, marked suspended: the address is
    /// installable again, though the slot itself only frees on reboot.
    fn write_breakpoint_after_reclaim(&mut self, addr: u64, processor: u16) -> Result<u32> {
        let reclaimed = self.reclaim_stranded_breakpoints(processor);
        if reclaimed == 0 {
            return Err(Self::breakpoint_table_error(addr));
        }
        self.notices.extend(reclaimed_breakpoints_notice(reclaimed));
        match with_framing_read_timeout_raw(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_breakpoint(framing, processor, addr)
        }) {
            Ok(handle) => Ok(handle),
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                Err(Self::breakpoint_table_error(addr))
            }
            Err(error) => Err(error),
        }
    }

    /// Release every table handle this session does not own, reporting how many
    /// the target accepted. A handle for a free slot is refused, so the count is
    /// the number of entries actually recovered.
    fn reclaim_stranded_breakpoints(&mut self, processor: u16) -> usize {
        let owned: HashSet<u32> = self.bp_handles.values().copied().collect();
        let Ok(framing) = self.link.framing(self.running_reason) else {
            return 0;
        };
        restore_unowned_breakpoint_handles(framing, processor, &owned, &mut self.released_handles)
    }

    /// Name the cause the raw NTSTATUS hides. WinDbg reports this as
    /// `Win32 error 0n998`, "invalid access to memory location", which sends
    /// people hunting a memory-access problem that does not exist.
    fn breakpoint_table_error(addr: u64) -> Error {
        Error::Kd(format!(
            "target refused a breakpoint at {addr:#x}: all {KD_BREAKPOINT_TABLE_SIZE} entries in \
             its breakpoint table are taken; entries an earlier session stranded in a page the \
             target can no longer write back only clear when the guest reboots"
        ))
    }

    /// Exit absorbs stray single-steps the same way run-control does: clear TF
    /// on the stopped vCPU, then continue. Otherwise a leaked TF can retrigger
    /// until exit gives up.
    fn absorb_stray_single_step_for_exit(&mut self, stop: &StopEvent) {
        if exit_stop_is_stray_single_step(stop, &self.managed_bp_addresses) {
            // record_stop selected the stop's processor, so this clears TF on the
            // offending vCPU. Clone the map to avoid borrowing self twice.
            let register_map = self.register_map.clone();
            let _ = clear_trap_flag(self, &register_map);
        }
    }

    fn finish_for_exit(&mut self, leave_running: bool) -> Result<()> {
        if let Some(stop) = self.shutdown_pump_with_stop()? {
            self.record_stop(&stop);
        }
        self.restore_tracked_breakpoints();
        if !leave_running {
            return Ok(());
        }

        for _ in 0..KD_EXIT_MAX_CONTINUES {
            if self.link.is_running() {
                match self.try_wait_for_stop(KD_EXIT_STOP_POLL)? {
                    None => return Ok(()),
                    Some(stop) => self.absorb_stray_single_step_for_exit(&stop),
                }
            }
            self.continue_stopped_for_exit()?;
            match self.try_wait_for_stop(KD_EXIT_STOP_POLL)? {
                None => return Ok(()),
                Some(stop) => self.absorb_stray_single_step_for_exit(&stop),
            }
        }

        Err(Error::Kd(format!(
            "target kept stopping during debugger exit after {KD_EXIT_MAX_CONTINUES} continues"
        )))
    }

    /// Query the target identity needed by both host-memory validation and
    /// target-mediated KD memory.
    pub fn target_hints(&mut self) -> Result<KdTargetHints> {
        let processor = self.current_processor;
        let version = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_version(framing, processor)
        })?;
        let register_value = match self.arch {
            Arch::Amd64 => {
                let special = self.read_special_registers_uncached(processor)?;
                wire::read_u64(&special, KSPECIAL_REGISTERS_CR3_OFFSET)
            }
            Arch::Arm64 => {
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_machine_specific_register(framing, processor, ARM64_WINDBG_TTBR1_EL1)
                })?
            }
        };
        let kernel_dtb = normalize_kernel_dtb(self.arch, register_value);
        if kernel_dtb == 0 || version.kern_base == 0 || version.ps_loaded_module_list == 0 {
            return Err(Error::Kd(format!(
                "KD target did not expose usable discovery hints (dtb={kernel_dtb:#x}, base={:#x}, psmods={:#x})",
                version.kern_base, version.ps_loaded_module_list
            )));
        }
        self.kernel_dtb_override = kernel_dtb;
        kd_trace!(
            "kd: memory hints: dtb={kernel_dtb:#x} base={:#x} psmods={:#x} arch={:?}",
            version.kern_base,
            version.ps_loaded_module_list,
            self.arch
        );
        Ok(KdTargetHints {
            kernel_dtb,
            kernel_base: VirtAddr(version.kern_base),
            ps_loaded_module_list: VirtAddr(version.ps_loaded_module_list),
            arch: self.arch,
        })
    }

    /// Reject a local VM mapping unless it is demonstrably the KD target.
    ///
    /// The PE header checks static identity; the loaded-module-list links add a
    /// dynamic per-boot identity so an unrelated local VM running the same
    /// Windows build cannot be selected accidentally.
    pub fn validate_host_memory<P: MemoryOps<PhysAddr>>(
        &mut self,
        phys: &P,
        hints: KdTargetHints,
    ) -> Result<()> {
        let local = match hints.arch {
            Arch::Amd64 => AddressSpace::new(phys, hints.kernel_dtb),
            Arch::Arm64 => AddressSpace::new_arm64(phys, hints.kernel_dtb, hints.kernel_dtb),
        };
        for (address, len, label) in [
            (hints.kernel_base, 64usize, "kernel PE header"),
            (hints.ps_loaded_module_list, 16usize, "loaded-module list"),
        ] {
            let mut local_bytes = vec![0u8; len];
            local.read_bytes(address, &mut local_bytes)?;
            let processor = self.current_processor;
            let remote_bytes =
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_virtual_memory(framing, processor, address.0, len as u32)
                })?;
            if remote_bytes != local_bytes {
                return Err(Error::Kd(format!(
                    "host VM memory does not match KD target ({label} differs)"
                )));
            }
        }
        Ok(())
    }

    /// Convert a connected KD backend into synchronized debugger and memory
    /// handles after target hints have been collected. The memory handle
    /// serves every source: it is the whole memory source for `kd`, and the
    /// write path for `host`.
    pub fn into_remote_memory(self) -> (KdBackendHandle, KdMemory) {
        let register_map = self.register_map.clone();
        let backend_name = self.backend_name;
        let translations = Arc::clone(&self.translations);
        let inner = Arc::new(Mutex::new(self));
        (
            KdBackendHandle {
                inner: Arc::clone(&inner),
                register_map,
                backend_name,
            },
            KdMemory {
                inner,
                translations,
            },
        )
    }

    fn require_remote_memory_stopped(&self) -> Result<()> {
        if self.link.is_running() {
            return Err(Error::TargetRunning(self.running_reason));
        }
        self.require_no_pending_write_breakpoint()
    }

    fn read_physical_bytes(&mut self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory read address overflow".into()))?;
            let requested = (buf.len() - completed).min(KD_REMOTE_MEMORY_CHUNK);
            let data =
                match with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_physical_memory(framing, processor, chunk_addr, requested as u32)
                }) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadPhysicalAddress(chunk_addr));
                    }
                    Err(error) => return Err(error),
                };
            kd_trace!(
                "kd: remote physical read {chunk_addr:#x}+{requested:#x} -> {:#x} {:02x?}",
                data.len(),
                &data[..data.len().min(8)]
            );
            let end = completed + data.len();
            buf[completed..end].copy_from_slice(&data);
            completed = end;
        }
        Ok(())
    }

    /// Page-table entries for the host page walk, a line of them per
    /// request: a walk of adjacent pages shares its upper-level entries and
    /// its run of PTEs, so the four reads a page costs become closer to one.
    fn read_page_table_bytes(&mut self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory read address overflow".into()))?;
            let line = chunk_addr & !(KD_VIRTUAL_LINE as u64 - 1);
            let offset = (chunk_addr - line) as usize;
            if self.table_lines.get(line).is_none() {
                let data = match with_framing_read_timeout(
                    self.framing()?,
                    KD_REQUEST_TIMEOUT,
                    |framing| {
                        api::read_physical_memory(framing, processor, line, KD_VIRTUAL_LINE as u32)
                    },
                ) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadPhysicalAddress(chunk_addr));
                    }
                    Err(error) => return Err(error),
                };
                kd_trace!(
                    "kd: remote table read {line:#x}+{KD_VIRTUAL_LINE:#x} -> {:#x}",
                    data.len()
                );
                self.table_lines.insert(line, data);
            }
            let data = self.table_lines.get(line).expect("line was just inserted");
            let available = data.len().saturating_sub(offset);
            if available == 0 {
                return Err(Error::BadPhysicalAddress(chunk_addr));
            }
            let end = completed + available.min(buf.len() - completed);
            buf[completed..end].copy_from_slice(&data[offset..offset + end - completed]);
            completed = end;
        }
        Ok(())
    }

    fn write_physical_bytes(&mut self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        // The write may land in a page table.
        self.translations.clear();
        self.virtual_lines.clear();
        self.table_lines.clear();
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("physical-memory write address overflow".into()))?;
            let requested = (buf.len() - completed).min(KD_REMOTE_MEMORY_CHUNK);
            let written =
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::write_physical_memory(
                        framing,
                        processor,
                        chunk_addr,
                        &buf[completed..completed + requested],
                    )
                })? as usize;
            completed += written;
        }
        Ok(())
    }

    /// `DbgKdReadVirtualMemoryApi` resolves through the current processor's
    /// page tables: kernel space, which every root maps alike, and user
    /// space under the root that processor is running on. Both take one
    /// request per line where the host walk costs four page-table reads per
    /// page first. User space under any other root keeps the walk: the API
    /// has no address-space selector.
    fn read_virtual_direct(
        &mut self,
        addr: VirtAddr,
        root: Dtb,
        buf: &mut [u8],
    ) -> Option<Result<()>> {
        if !self.virtual_api_serves(addr, root) {
            return None;
        }
        Some(self.read_virtual_bytes(addr, buf))
    }

    /// Whether `DbgKd{Read,Write}VirtualMemoryApi` resolves `addr` in the
    /// `root` address space. Kernel space is the same under every root, save
    /// session space, which the API resolves in the halted processor's
    /// session (as WinDbg does); user space only under the root the current
    /// processor is running on.
    fn virtual_api_serves(&mut self, addr: VirtAddr, root: Dtb) -> bool {
        let kernel_space = match self.arch {
            Arch::Amd64 => addr.0 >> 63 != 0,
            Arch::Arm64 => addr.0 & (1 << 55) != 0,
        };
        kernel_space || self.current_processor_runs_on(root)
    }

    /// Whether `root` is the page-table root the current processor is
    /// running on. AMD64 only: its CR3 sits in the special registers cached
    /// per halt, while the ARM64 user root (TTBR0) would cost a request of
    /// its own to learn.
    fn current_processor_runs_on(&mut self, root: Dtb) -> bool {
        if self.arch != Arch::Amd64 || self.require_remote_memory_stopped().is_err() {
            return false;
        }
        let Ok(special) = self.read_special_registers() else {
            return false;
        };
        let cr3 = wire::read_u64(special, KSPECIAL_REGISTERS_CR3_OFFSET);
        let mask = self.arch.dtb_page_mask();
        cr3 & mask == root & mask
    }

    /// The write twin of [`Self::read_virtual_direct`], eligible in exactly
    /// the same address spaces.
    ///
    /// `DbgKdWriteVirtualMemoryApi` is serviced by the guest's own
    /// debug-memory path, which honors the page's write protection,
    /// copy-on-write state and residency. Writing the frame instead, through
    /// a host mapping or `DbgKdWritePhysicalMemory`, honors none of those: it
    /// can modify a page the guest believes is read-only or shared, and a
    /// frame the guest reclaims afterwards carries the edit to whatever lands
    /// there next.
    fn write_virtual_direct(
        &mut self,
        addr: VirtAddr,
        root: Dtb,
        buf: &[u8],
    ) -> Option<Result<()>> {
        if !self.virtual_api_serves(addr, root) {
            return None;
        }
        Some(self.write_virtual_bytes(addr, buf))
    }

    fn write_virtual_bytes(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        // The write may land in a page table.
        self.translations.clear();
        self.virtual_lines.clear();
        self.table_lines.clear();
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .0
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("virtual-memory write address overflow".into()))?;
            let to_page_end = PAGE_SIZE - (chunk_addr as usize & (PAGE_SIZE - 1));
            let requested = (buf.len() - completed)
                .min(KD_REMOTE_MEMORY_CHUNK)
                .min(to_page_end);
            let written =
                match with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::write_virtual_memory(
                        framing,
                        processor,
                        chunk_addr,
                        &buf[completed..completed + requested],
                    )
                }) {
                    Ok(written) => written as usize,
                    // The target refuses a page it will not write: unmapped,
                    // or protected in a way a physical poke would have
                    // silently defeated.
                    Err(Error::KdStatus { .. }) if completed > 0 => {
                        return Err(Error::PartialWrite(completed));
                    }
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadVirtualAddress(VirtAddr(chunk_addr)));
                    }
                    Err(error) => return Err(error),
                };
            if written == 0 {
                return Err(Error::PartialWrite(completed));
            }
            kd_trace!(
                "kd: remote virtual write {chunk_addr:#x}+{written:#x} {:02x?}",
                &buf[completed..completed + written.min(8)]
            );
            completed += written;
        }
        Ok(())
    }

    /// A miss reads from the start of its line to the end of the request,
    /// rounded up to lines and capped at a chunk and a page: the fields of a
    /// structure cost one request between them, and a large read costs the
    /// same chunks it always did. Lines never cross a page, and a page is
    /// mapped or not as a whole, so a refused fill is exactly the hole a
    /// page walk reports. A reply shorter than the fill is the transport's
    /// limit, not a hole: its whole lines are kept and the rest asked for
    /// again.
    fn read_virtual_bytes(&mut self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let request_end = addr
            .0
            .checked_add(buf.len() as u64)
            .ok_or_else(|| Error::Kd("virtual-memory read address overflow".into()))?;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr.0 + completed as u64;
            let line = chunk_addr & !(KD_VIRTUAL_LINE as u64 - 1);
            let offset = (chunk_addr - line) as usize;
            let refused = |completed: usize| {
                if completed > 0 {
                    Error::PartialRead(completed)
                } else {
                    Error::BadVirtualAddress(VirtAddr(chunk_addr))
                }
            };
            if self.virtual_lines.get((processor, line)).is_none() {
                let wanted = request_end.next_multiple_of(KD_VIRTUAL_LINE as u64) - line;
                let to_page_end = PAGE_SIZE as u64 - (line & (PAGE_SIZE as u64 - 1));
                let fill = wanted.min(self.virtual_fill_cap as u64).min(to_page_end) as usize;
                let data = match with_framing_read_timeout(
                    self.framing()?,
                    KD_REQUEST_TIMEOUT,
                    |framing| api::read_virtual_memory(framing, processor, line, fill as u32),
                ) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) => return Err(refused(completed)),
                    Err(error) => return Err(error),
                };
                kd_trace!(
                    "kd: remote virtual read {line:#x}+{fill:#x} -> {:#x}",
                    data.len()
                );
                let whole = data.len() / KD_VIRTUAL_LINE * KD_VIRTUAL_LINE;
                if whole == 0 {
                    return Err(refused(completed));
                }
                if data.len() < fill {
                    self.virtual_fill_cap = whole;
                }
                for (index, piece) in data[..whole].chunks(KD_VIRTUAL_LINE).enumerate() {
                    self.virtual_lines.insert(
                        (processor, line + (index * KD_VIRTUAL_LINE) as u64),
                        piece.to_vec(),
                    );
                }
            }
            let data = self
                .virtual_lines
                .get((processor, line))
                .expect("line was just inserted");
            let end = completed + (data.len() - offset).min(buf.len() - completed);
            buf[completed..end].copy_from_slice(&data[offset..offset + end - completed]);
            completed = end;
        }
        Ok(())
    }

    fn needs_drop_cleanup(&self) -> bool {
        !self.exit_prepared && matches!(self.link, Link::Halted(_) | Link::RunningPumped(_))
    }
}

impl DebugBackend for KdBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn name(&self) -> &'static str {
        self.backend_name
    }

    fn set_kernel_dtb(&mut self, dtb: u64) {
        self.kernel_dtb_override = dtb;
        kd_trace!("kd: kernel page-table root = {dtb:#x}");
    }

    /// The selected processor's register context, memoized for the halt.
    ///
    /// A full `CONTEXT` is a request/reply exchange plus the control-register
    /// and EFER reads layered on top, and one stop asks for it repeatedly: the
    /// `int3` rewind, the stop classification, the step-over and the trap-flag
    /// cleanup all want the same bytes. Nothing but this debugger can change
    /// them while the target is halted, so the fetch happens once and is
    /// invalidated on resume and after a write, the same contract as
    /// `special_register_cache`.
    fn read_registers(&mut self) -> Result<Vec<u8>> {
        if let Some(cached) = self.context_cache.get(&self.current_processor) {
            return Ok(cached.clone());
        }
        kd_trace!(
            "kd: read_registers: GetContext on p{}",
            self.current_processor + 1
        );
        let processor = self.current_processor;
        let context_flags = self.context_flags();
        let mut ctx = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_context(framing, processor, context_flags)
        })?;
        kd_trace!("kd: read_registers: got {} context bytes", ctx.len());
        self.append_control_registers(&mut ctx)?;
        if self.arch == Arch::Amd64 {
            let efer = self.efer_cache.get(&processor).copied().or_else(|| {
                match self.read_msr_value(processor, MSR_EFER) {
                    Ok(value) => {
                        self.efer_cache.insert(processor, value);
                        Some(value)
                    }
                    Err(error) => {
                        kd_trace!("kd: EFER read unavailable: {error}");
                        None
                    }
                }
            });
            if let Some(efer) = efer {
                wire::write_u64(&mut ctx, context::OFFSET_EFER, efer);
            }
        }
        kd_trace!("kd: read_registers: extended to {} bytes", ctx.len());
        if trace_enabled() {
            let cr3 = self.register_map.read_u64("cr3", &ctx).unwrap_or(0);
            let pc = self.register_map.read_u64("pc", &ctx).unwrap_or(0);
            let sp = self.register_map.read_u64("sp", &ctx).unwrap_or(0);
            kd_trace!("kd: read_registers: cr3={cr3:#x} pc={pc:#x} sp={sp:#x}");
        }
        self.context_cache.insert(processor, ctx.clone());
        Ok(ctx)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let processor = self.current_processor;
        // The written values become the truth only once the target has them.
        self.context_cache.remove(&processor);
        match self.arch {
            Arch::Amd64 => {
                let context = context_payload(data)?;
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::set_context_chunked(framing, processor, context)
                })?;

                // KD restores hardware-breakpoint state from KSPECIAL_REGISTERS,
                // not the CONTEXT debug-register fields. Keep both views
                // coherent so DR6 clearing and DR7 updates survive ContinueApi2.
                let mut special = self.read_special_registers_uncached(self.current_processor)?;
                update_special_debug_registers_from_context(&mut special, data)?;
                self.write_special_registers(special)
            }
            Arch::Arm64 => {
                if data.len() < context_arm64::CONTEXT_SIZE {
                    return Err(Error::Kd(format!(
                        "ARM64 CONTEXT buffer too short: {} bytes, expected {}",
                        data.len(),
                        context_arm64::CONTEXT_SIZE
                    )));
                }
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::set_context_chunked(
                        framing,
                        processor,
                        &data[..context_arm64::CONTEXT_SIZE],
                    )
                })?;
                // ARM64 hardware state is authoritative in KSPECIAL_REGISTERS,
                // while CONTEXT exposes the same BVR/BCR and WVR/WCR fields.
                // Keep both views coherent when a full context is written. The
                // SetContext above already carried those fields, so a target
                // that refuses control space must not fail an applied write.
                if self.special_registers_unsupported {
                    return Ok(());
                }
                let mut special = match self.read_special_registers_uncached(processor) {
                    Ok(special) => special,
                    Err(error) => {
                        kd_trace!("kd: ARM64 KSPECIAL_REGISTERS mirror skipped: {error}");
                        self.special_registers_unsupported = true;
                        return Ok(());
                    }
                };
                update_arm64_debug_registers_from_context(&mut special, data)?;
                self.write_special_registers(special)
            }
        }
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.complete_pending_write_breakpoint(addr)? {
            return Ok(());
        }

        // The target patches the site itself; every line read from here on
        // must see it.
        self.virtual_lines.clear();
        let processor = self.current_processor;
        let result =
            with_framing_read_timeout_raw(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                api::write_breakpoint(framing, processor, addr)
            });
        let handle = match result {
            Ok(handle) => handle,
            Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => {
                self.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor });
                return Err(Error::Kd(format!(
                    "KD request timed out after {}s; breakpoint install is pending, retry the same bp command to complete it",
                    KD_REQUEST_TIMEOUT.as_secs()
                )));
            }
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_WRITE_BREAKPOINT =>
            {
                self.write_breakpoint_after_reclaim(addr, processor)?
            }
            Err(err) => return Err(err),
        };
        kd_trace!("kd: write_breakpoint: {addr:#x} -> handle {handle}");
        self.bp_handles.insert(addr, handle);
        self.managed_bp_addresses.insert(addr);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let handle = *self
            .bp_handles
            .get(&addr)
            .ok_or_else(|| Error::Kd(format!("no breakpoint tracked at {addr:#x}")))?;
        self.virtual_lines.clear();
        let processor = self.current_processor;
        let result = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        });
        match result {
            Ok(()) => {}
            Err(Error::KdStatus { ntstatus, api })
                if ntstatus == STATUS_UNSUCCESSFUL && api == api::DBGKD_RESTORE_BREAKPOINT =>
            {
                // The target refuses a handle whose table entry it has
                // already reclaimed, which is what a stop does to every
                // entry it suspends. That is only the harmless answer if the
                // site is clean: forgetting an address that still holds the
                // breakpoint instruction leaves an `int3` no one claims, and
                // the next resume steps the program counter past it and into
                // the middle of the instruction it displaced. Keep the
                // handle so a retry (and exit) can still release the entry.
                let arch = self.arch;
                if breakpoint_instruction_at(
                    self.link.framing(self.running_reason)?,
                    arch,
                    processor,
                    addr,
                ) {
                    return Err(Error::Kd(format!(
                        "target refused to release the breakpoint at {addr:#x} (handle {handle}) \
                         and the site still holds a breakpoint instruction"
                    )));
                }
                kd_trace!(
                    "kd: restore breakpoint handle {handle} at {addr:#x} was already consumed"
                );
            }
            // Transport failure: the site may still be patched, so keep
            // tracking it (a retry restores it; a hit there is still ours).
            Err(e) => return Err(e),
        }
        self.bp_handles.remove(&addr);
        self.managed_bp_addresses.remove(&addr);
        Ok(())
    }

    fn supports_watchpoints(&self) -> bool {
        // Both architectures expose per-processor debug state through KD
        // KSPECIAL_REGISTERS (DR0-DR7 on AMD64; BVR/BCR and WVR/WCR on ARM64).
        matches!(self.arch, Arch::Amd64 | Arch::Arm64)
    }

    fn hardware_breakpoint_slots(&self) -> u8 {
        match self.arch {
            Arch::Amd64 => HW_BREAKPOINT_SLOTS,
            Arch::Arm64 => hwbp::ARM64_MAX_BREAKPOINTS + hwbp::ARM64_MAX_WATCHPOINTS,
        }
    }

    fn hardware_slot_range(&self, access: HwBreakpointAccess) -> std::ops::Range<u8> {
        match self.arch {
            Arch::Amd64 => 0..HW_BREAKPOINT_SLOTS,
            Arch::Arm64 => hwbp::arm64_slot_range(access),
        }
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        match self.arch {
            Arch::Amd64 => {
                // DR state is per-processor, so program every CPU: watched code
                // can run anywhere. The shared transaction prevents an
                // untracked partial set.
                self.update_slot_on_all_processors(
                    slot,
                    "install",
                    "hardware breakpoint",
                    |backend, slot| backend.read_dr_slot_state(slot),
                    |backend, slot, state| backend.apply_dr_restore(slot, state),
                    |backend| backend.apply_dr_set(slot, addr, access, len),
                )
            }
            Arch::Arm64 => {
                arm64_slot_offsets_for_access(slot, access)?;
                self.update_slot_on_all_processors(
                    slot,
                    "install",
                    "ARM64 hardware breakpoint",
                    |backend, slot| backend.read_arm64_slot_state(slot),
                    |backend, slot, state| backend.apply_arm64_restore(slot, state),
                    |backend| backend.apply_arm64_set(slot, addr, access, len),
                )
            }
        }
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        // A failed disable/remove must leave the manager's still-enabled entry
        // truthful, so clearing receives the same rollback guarantee as set.
        match self.arch {
            Arch::Amd64 => self.update_slot_on_all_processors(
                slot,
                "clear",
                "hardware breakpoint",
                |backend, slot| backend.read_dr_slot_state(slot),
                |backend, slot, state| backend.apply_dr_restore(slot, state),
                |backend| backend.apply_dr_clear(slot),
            ),
            Arch::Arm64 => {
                arm64_slot_offsets(slot)?;
                self.update_slot_on_all_processors(
                    slot,
                    "clear",
                    "ARM64 hardware breakpoint",
                    |backend, slot| backend.read_arm64_slot_state(slot),
                    |backend, slot, state| backend.apply_arm64_restore(slot, state),
                    |backend| backend.apply_arm64_clear(slot),
                )
            }
        }
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        // GuestMemoryPatch emits `int3` on AMD64 and `brk #0xF000` on ARM64.
        matches!(self.arch, Arch::Amd64 | Arch::Arm64)
    }

    fn supports_msr(&self) -> bool {
        true
    }

    fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        self.validate_processor(processor)?;
        self.read_msr_value(processor, msr)
    }

    fn write_msr(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        self.validate_processor(processor)?;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_machine_specific_register(framing, processor, msr, value)
        })?;
        if msr == MSR_EFER {
            self.efer_cache.insert(processor, value);
        }
        Ok(())
    }

    fn supports_target_control(&self) -> bool {
        true
    }

    fn supports_target_file_io(&self) -> bool {
        true
    }

    fn reboot_target(&mut self) -> Result<()> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::reboot(framing, processor)
        })?;
        // Reboot has no manipulate-state reply: after the transport ACK the
        // kernel resets the KD stream and eventually emits a fresh state
        // change. Keep the backend visibly running and let the pump perform
        // the existing reconnect/reload detection dance.
        self.record_running();
        self.start_pump(Some(Duration::ZERO), None)
    }

    fn cause_bugcheck(&mut self) -> Result<()> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::cause_bugcheck(framing, processor)
        })?;
        // KeBugCheck2 skips the fatal print and the first debugger break for
        // MANUALLY_INITIATED_CRASH: the target writes its dump (tens of seconds,
        // interrupts off, break-ins ignored) and then reboots, or breaks in
        // afterwards when automatic restart is disabled. Treat it like a reboot,
        // but do not poke immediately: the kernel still polls for break-ins on
        // its way into KeBugCheck2 and an early poke detours it into a stop.
        self.record_running();
        self.start_pump(Some(POST_BUGCHECK_RECONNECT_ASSIST_DELAY), None)
    }

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability {
                capability: DebugCapability::UserModeBreakpoints,
                supported: self.supports_user_mode_breakpoints(),
            },
            BackendCapability {
                capability: DebugCapability::Watchpoints,
                supported: self.supports_watchpoints(),
            },
            BackendCapability::supported(DebugCapability::TargetReloadDetection),
            BackendCapability::supported(DebugCapability::KernelBaseHint),
            BackendCapability::supported(DebugCapability::BugcheckDetection),
            BackendCapability::supported(DebugCapability::BugcheckDetails),
            BackendCapability::supported(DebugCapability::DebugOutput),
            BackendCapability {
                capability: DebugCapability::Msr,
                supported: self.supports_msr(),
            },
            BackendCapability {
                capability: DebugCapability::TargetControl,
                supported: self.supports_target_control(),
            },
            BackendCapability {
                capability: DebugCapability::TargetFileIo,
                supported: self.supports_target_file_io(),
            },
        ]
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.debug_log.read_since(since_seq)
    }

    fn take_notices(&mut self) -> Vec<String> {
        let mut notices = std::mem::take(&mut self.notices);
        notices.extend(kd_files().take_served());
        notices
    }

    fn note_breakpoint_installed(&mut self, addr: u64) {
        self.managed_bp_addresses.insert(addr);
    }

    fn note_breakpoint_uninstalled(&mut self, addr: u64) {
        self.managed_bp_addresses.remove(&addr);
    }

    /// The target's `KdpBreakpointTable` owns every site written through
    /// `DbgKdWriteBreakPointApi`: the kernel keeps the displaced bytes and
    /// hides them from memory reads. It does not, however, step the
    /// reporting thread over its own site; see [`Self::sites_dropped_by_stop`].
    fn target_manages_breakpoint_sites(&self) -> bool {
        true
    }

    /// `KdpReportExceptionStateChange` calls `KdpDeleteBreakpointRange` over
    /// the `DBGKD_MAXSTREAM` bytes it reports from the stop PC, so every
    /// table entry there is gone (and its handle dead) once the stop is on
    /// the wire. The full window is reported even when the stream was cut
    /// short by a page end: rewriting a surviving entry only churns it.
    fn sites_dropped_by_stop(&self) -> Vec<u64> {
        let window = self.last_rip..self.last_rip.saturating_add(api::DBGKD_MAXSTREAM);
        self.bp_handles
            .keys()
            .copied()
            .filter(|addr| window.contains(addr))
            .collect()
    }

    fn note_target_rediscovery_pending(&mut self) {
        self.reconnect_assist_after_continue = Some(Duration::ZERO);
    }

    fn note_target_rediscovery_complete(&mut self) {
        self.reconnect_assist_after_continue = None;
    }

    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_version(framing, processor).map(|version| Some(VirtAddr(version.kern_base)))
        })
    }

    fn target_debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::get_version(framing, processor).map(|version| {
                (version.flags & api::DBGKD_VERS_FLAG_DATA != 0 && version.debugger_data_list != 0)
                    .then_some(DebuggerDataCandidate {
                        address: VirtAddr(version.debugger_data_list),
                        source: MetadataSource::KdVersion,
                    })
            })
        })
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.continue_execution_with_disposition(ContinueDisposition::Handled)
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        let resume_processor = self.last_stop_processor;
        self.skip_hardcoded_breakpoint(resume_processor)?;
        // The pump absorbs the re-break a stale break-in byte causes right
        // after resume; it needs to know where we resumed from and which
        // breakpoints are real. Nothing can change either while the VM runs.
        let drain = ContinueDrain::new(
            self.last_rip,
            self.managed_bp_addresses.clone(),
            self.breakin_addresses.clone(),
            self.register_map.clone(),
        );
        let reconnect_assist_after_continue = self.reconnect_assist_after_continue;
        kd_trace!(
            "kd: continue: sending ContinueApi2 on p{}",
            resume_processor + 1
        );
        self.continue_preserving_dr7(
            resume_processor,
            api::status_for_disposition(disposition),
            false,
        )?;
        kd_trace!("kd: continue: ContinueApi2 ACKed, VM should resume");
        self.record_running();
        // Hand the socket to the background pump so prints keep getting ACKed
        // (and the debugger stays "present") until the next stop.
        self.start_pump(reconnect_assist_after_continue, Some(drain))
    }

    fn step(&mut self) -> Result<()> {
        // Managed BP step-over needs to execute the original instruction. A
        // single step stops almost immediately, so the caller's wait_for_stop
        // reads it synchronously; no pump needed
        let processor = self.current_processor;
        // A raw int3 stop still points at the int3; stepping from there would
        // only execute it again and report the same stop.
        if processor == self.last_stop_processor {
            self.skip_hardcoded_breakpoint(processor)?;
        }
        self.continue_preserving_dr7(processor, api::DBG_CONTINUE, true)?;
        self.record_running();
        Ok(())
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        let stop = if let Link::RunningPumped(pump) = &self.link {
            // Pump owns the socket; poke the kernel with a break-in over the
            // cloned fd, then collect the state-change the pump reports back.
            // Flag it first: the stop lands at the KD break-in instruction,
            // where the pump would otherwise absorb it as post-continue noise.
            pump.breakin_requested.store(true, Ordering::SeqCst);
            self.send_raw_breakin()?;
            match self.take_pump_stop(Some(Duration::from_secs(10)))? {
                Some(stop) => stop,
                None => {
                    self.shutdown_pump();
                    return Err(Error::Kd("no break-in response within 10s".into()));
                }
            }
        } else {
            // Stopped, or running via a bare step: drive the break-in inline
            let arch = self.arch;
            breakin_and_wait(self.framing()?, arch, Duration::from_secs(10))?
        };
        self.record_stop(&stop);
        Ok(stop_event(stop))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        if matches!(self.link, Link::RunningPumped(_)) {
            let stop = self
                .take_pump_stop(None)?
                .ok_or_else(|| Error::Kd("KD pump returned no stop".into()))?;
            let stop = self.mark_known_breakin_stop(stop);
            self.record_stop(&stop);
            return Ok(stop_event(stop));
        }
        let debug_log = self.debug_log.clone();
        let arch = self.arch;
        // Request paths leave shorter timeouts in place; a blocking wait needs a long one.
        let _ = self
            .framing()?
            .transport_mut()
            .set_read_timeout(Some(blocking_read_timeout()));
        let stop = await_state_change(
            self.framing()?,
            AwaitStateOptions {
                arch,
                saw_kd_refresh: None,
                surface_all: false,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: None,
                debug_log: Some(&debug_log),
            },
        )?;
        let stop = self.mark_known_breakin_stop(stop);
        self.record_stop(&stop);
        Ok(stop_event(stop))
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        // Pump path: the background thread already services the socket and
        // detects stops, so just poll it. This is the common case while running
        if matches!(self.link, Link::RunningPumped(_)) {
            return match self.take_pump_stop(Some(timeout))? {
                Some(stop) => {
                    let stop = self.mark_known_breakin_stop(stop);
                    kd_trace!(
                        "kd: try_wait: pump reported stop rip={:#x} exc={:#x}",
                        stop.program_counter,
                        stop.exception_code
                    );
                    self.record_stop(&stop);
                    Ok(Some(stop_event(stop)))
                }
                None => Ok(None),
            };
        }
        // Synchronous fallback (no pump, e.g. polling after a bare step)
        self.framing()?
            .transport_mut()
            .set_read_timeout(Some(timeout))?;
        let mut saw_kd_refresh = false;
        let debug_log = self.debug_log.clone();
        let arch = self.arch;
        let result = await_state_change(
            self.framing()?,
            AwaitStateOptions {
                arch,
                saw_kd_refresh: Some(&mut saw_kd_refresh),
                surface_all: false,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: Some(Instant::now() + timeout),
                debug_log: Some(&debug_log),
            },
        );

        let stop = match result {
            Ok(stop) => stop,
            Err(Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                if saw_kd_refresh {
                    kd_trace!("kd: try_wait: KD refresh observed while polling");
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let stop = self.mark_known_breakin_stop(stop);
        kd_trace!(
            "kd: try_wait: stop rip={:#x} exc={:#x} in_managed={}",
            stop.program_counter,
            stop.exception_code,
            self.managed_bp_addresses.contains(&stop.program_counter)
        );

        self.record_stop(&stop);
        Ok(Some(stop_event(stop)))
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok((0..self.processor_count).map(thread_id_for).collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        // Local-only; SwitchProcessor emits an unsolicited state-change
        self.current_processor =
            parse_thread_id_for_processor_count(thread_id, self.processor_count)?;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        Ok(thread_id_for(self.current_processor))
    }

    fn is_running(&self) -> bool {
        self.link.is_running()
    }

    fn has_pending_stop(&self) -> bool {
        // The pump reported a stop nobody has drained yet; `is_running` is stale.
        matches!(&self.link, Link::RunningPumped(pump) if pump.reported_stop.load(Ordering::SeqCst))
    }

    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        let result = self.finish_for_exit(leave_running);
        if result.is_ok() {
            self.exit_prepared = true;
        }
        result
    }
}

impl DebugBackend for KdBackendHandle {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn revalidate_host_memory(&mut self, phys: &PhysMem) -> Result<()> {
        let mut backend = self.lock();
        let hints = backend.target_hints()?;
        backend.validate_host_memory(phys, hints)
    }

    fn name(&self) -> &'static str {
        self.backend_name
    }

    fn set_kernel_dtb(&mut self, dtb: u64) {
        self.lock().set_kernel_dtb(dtb);
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.lock().read_registers()
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.lock().write_registers(data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.lock().set_breakpoint(addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.lock().remove_breakpoint(addr)
    }

    fn supports_watchpoints(&self) -> bool {
        self.lock().supports_watchpoints()
    }

    fn hardware_breakpoint_slots(&self) -> u8 {
        self.lock().hardware_breakpoint_slots()
    }

    fn hardware_slot_range(&self, access: HwBreakpointAccess) -> std::ops::Range<u8> {
        self.lock().hardware_slot_range(access)
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        self.lock().set_hardware_breakpoint(slot, addr, access, len)
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        self.lock().clear_hardware_breakpoint(slot)
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        self.lock().supports_user_mode_breakpoints()
    }

    fn supports_msr(&self) -> bool {
        self.lock().supports_msr()
    }

    fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        self.lock().read_msr(processor, msr)
    }

    fn write_msr(&mut self, processor: u16, msr: u32, value: u64) -> Result<()> {
        self.lock().write_msr(processor, msr, value)
    }

    fn supports_target_control(&self) -> bool {
        self.lock().supports_target_control()
    }

    fn supports_target_file_io(&self) -> bool {
        self.lock().supports_target_file_io()
    }

    fn reboot_target(&mut self) -> Result<()> {
        self.lock().reboot_target()
    }

    fn cause_bugcheck(&mut self) -> Result<()> {
        self.lock().cause_bugcheck()
    }

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        self.lock().optional_capabilities()
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.lock().read_debug_output(since_seq)
    }

    fn take_notices(&mut self) -> Vec<String> {
        self.lock().take_notices()
    }

    fn note_breakpoint_installed(&mut self, addr: u64) {
        self.lock().note_breakpoint_installed(addr);
    }

    fn note_breakpoint_uninstalled(&mut self, addr: u64) {
        self.lock().note_breakpoint_uninstalled(addr);
    }

    fn note_target_rediscovery_pending(&mut self) {
        self.lock().note_target_rediscovery_pending();
    }

    fn note_target_rediscovery_complete(&mut self) {
        self.lock().note_target_rediscovery_complete();
    }

    fn target_manages_breakpoint_sites(&self) -> bool {
        self.lock().target_manages_breakpoint_sites()
    }

    fn sites_dropped_by_stop(&self) -> Vec<u64> {
        self.lock().sites_dropped_by_stop()
    }

    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        self.lock().target_kernel_base_hint()
    }

    fn target_debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        self.lock().target_debugger_data_hint()
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.lock().continue_execution()
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        self.lock().continue_execution_with_disposition(disposition)
    }

    fn step(&mut self) -> Result<()> {
        self.lock().step()
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        self.lock().interrupt()
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        self.lock().wait_for_stop()
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.lock().try_wait_for_stop(timeout)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        self.lock().thread_list()
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        self.lock().set_current_thread(thread_id)
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        self.lock().stopped_thread_id()
    }

    fn is_running(&self) -> bool {
        self.lock().is_running()
    }

    fn has_pending_stop(&self) -> bool {
        self.lock().has_pending_stop()
    }

    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        self.lock().prepare_for_exit(leave_running)
    }
}
/// Best-effort resume during normal teardown
impl Drop for KdBackend {
    fn drop(&mut self) {
        if self.needs_drop_cleanup() {
            let _ = self.finish_for_exit(true);
        }
    }
}

#[cfg(test)]
mod tests;
