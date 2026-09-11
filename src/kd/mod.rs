use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use owo_colors::OwoColorize;

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
use crate::session::clear_trap_flag;
use crate::types::{Arch, Dtb, PhysAddr, VirtAddr};

macro_rules! kd_trace {
    ($($arg:tt)*) => {
        if $crate::kd::trace_enabled() {
            eprintln!($($arg)*);
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

const DBG_KD_EXCEPTION_STATE_CHANGE: u32 = 0x0000_3030;
/// Symbol load/unload notification. The kernel emits these (including during
/// bugcheck via KiBugcheckUnloadDebugSymbols); WinDbg acknowledges and resumes
/// rather than presenting a user break
const DBG_KD_LOAD_SYMBOLS_STATE_CHANGE: u32 = 0x0000_3031;
/// Command-string notification (e.g. `.echo` from the target); also transparent
const DBG_KD_COMMAND_STRING_STATE_CHANGE: u32 = 0x0000_3032;

const AMD64_DEBUG_CONTROL_SPACE_KSPECIAL: u64 = 2;

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
const KSPECIAL_REGISTERS_CR8_OFFSET: usize = 0xA0;
const KSPECIAL_REGISTERS_MIN_SIZE: usize = KSPECIAL_REGISTERS_CR8_OFFSET + 8;
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
const KD_REFRESH_MESSAGE: &[u8] = b"KDTARGET: Refreshing KD connection";
const KD_INITIAL_TIMEOUT_ENV: &str = "NTOSEYE_KD_TIMEOUT";
const KD_INITIAL_TIMEOUT_DEFAULT: Duration = Duration::from_secs(8);
const KD_INITIAL_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);
const KD_REFRESH_BREAKIN_INTERVAL: Duration = Duration::from_millis(250);
const KD_REFRESH_BREAKIN_TRACE_EVERY: u32 = 8;
const BUGCHECK_REFRESH_ASSIST_GRACE: Duration = Duration::from_secs(2);
const POST_BUGCHECK_RECONNECT_ASSIST_DELAY: Duration = Duration::from_secs(20);
const BUGCHECK_MANUALLY_INITIATED_CRASH: u32 = 0x0000_00e2;
const KD_EXIT_STOP_POLL: Duration = Duration::from_secs(1);
const KD_EXIT_MAX_CONTINUES: u32 = 8;
/// How long the background pump blocks on a socket read before looping back to
/// check its shutdown flag. Incoming packets are still serviced immediately
/// (this only bounds shutdown latency); the kernel writes each packet as one
/// burst, so a timeout this size only ever fires in the idle gap between packets.
const PUMP_POLL: Duration = Duration::from_millis(100);
const KD_REMOTE_MEMORY_CHUNK: usize = 0x800;
const AMD64_DTB_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const ARM64_TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// Windows KD encoding of `TTBR1_EL1`: op0=3, op1=0, CRn=2, CRm=0, op2=1.
const ARM64_WINDBG_TTBR1_EL1: u32 = 0x0003_0201;

fn normalize_kernel_dtb(arch: Arch, register_value: u64) -> Dtb {
    match arch {
        Arch::Amd64 => register_value & AMD64_DTB_MASK,
        // Strip the 16-bit ASID and the possible upper-table 0x800 offset.
        Arch::Arm64 => register_value & ARM64_TTBR_BADDR_MASK,
    }
}

fn thread_id_for(processor: u16) -> String {
    format!("p1.{:x}", processor + 1)
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

fn should_advance_pc_before_continue(exception_code: u32, managed_breakpoint_stop: bool) -> bool {
    exception_code == STATUS_BREAKPOINT && !managed_breakpoint_stop
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
        assisted_breakin: stop.assisted_breakin,
    }
}

#[derive(Clone, Copy)]
struct DebugRegisterSlotState {
    address: u64,
    dr7: u64,
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
    fn framing(&mut self) -> Result<&mut KdFraming<KdTransport>> {
        match self {
            Self::Halted(framing) | Self::RunningInline(framing) => Ok(framing),
            Self::RunningPumped(_) => Err(Error::Kd("KD transport is busy: VM is running".into())),
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

pub struct KdBackend {
    link: Link,
    breakin_clone: KdTransport,
    backend_name: &'static str,
    register_map: RegisterMap,
    arch: Arch,
    /// Kernel page-table root, first read from the target at attach and
    /// later confirmed by the session: selects KD virtual reads for kernel
    /// space and, on ARM64, fills the synthetic `cr3` register slot.
    kernel_dtb_override: u64,
    processor_count: u16,
    current_processor: u16,
    last_stop_processor: u16,
    last_exception_code: u32,
    last_rip: u64,
    last_stop_was_managed_breakpoint: bool,
    reconnect_assist_after_continue: Option<Duration>,
    bp_handles: HashMap<u64, u32>,
    managed_bp_addresses: HashSet<u64>,
    breakin_addresses: HashSet<u64>,
    pending_write_breakpoint: Option<PendingWriteBreakpoint>,
    special_register_cache: HashMap<u16, Vec<u8>>,
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

    fn translation_cache(&self) -> Option<&TranslationCache> {
        Some(&self.translations)
    }
}

impl KdBackend {
    /// Connect to a KDCOM serial pipe and stop at the initial state-change.
    pub fn connect(socket_path: &str) -> Result<Self> {
        eprintln!(
            "{} {}",
            "kd: using KDCOM backend on".bright_black(),
            socket_path.cyan()
        );
        let stream = UnixStream::connect(socket_path)
            .map_err(|err| kd_socket_connect_error(socket_path, err))?;
        Self::connect_transport(
            KdTransport::Serial(stream),
            "kd: serial connected; waiting for Windows KD target",
            "kd",
        )
    }

    /// Listen for a KDNET target and stop at the initial state-change.
    pub fn connect_net(listen_addr: &str, key: &str) -> Result<Self> {
        eprintln!(
            "{} {}",
            "kdnet: listening on".bright_black(),
            listen_addr.cyan()
        );
        let stream = KdNetStream::bind(listen_addr, key)?;
        Self::connect_transport(
            KdTransport::Network(stream),
            "kdnet: listener ready; waiting for Windows KDNET target",
            "kdnet",
        )
    }

    fn connect_transport(
        transport: KdTransport,
        waiting_message: &str,
        backend_name: &'static str,
    ) -> Result<Self> {
        let network_generation = transport.network_session_generation();
        let mut framing = KdFraming::new(transport);
        if let Some(generation) = network_generation {
            framing.use_kdnet_packet_ids(generation);
        }
        let initial_timeout = kd_initial_timeout()?;

        eprintln!(
            "{}",
            format!("{waiting_message} (timeout {}s)", initial_timeout.as_secs()).bright_black()
        );

        // A waiting kernel retransmits state-change; otherwise break in.
        let mut initial_stop = poll_for_initial_break(&mut framing, initial_timeout)?;
        let version = match probe_initial_request(&mut framing, initial_stop.processor) {
            Ok(version) => version,
            Err(err) => {
                if !is_initial_resync_error(&err) {
                    return Err(err);
                }
                kd_trace!("kd: initial request probe failed ({err}); resetting KD packet stream");
                framing.send_reset()?;
                initial_stop = poll_for_initial_break(&mut framing, initial_timeout)?;
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
        let mut breakin_addresses = HashSet::new();
        if initial_stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE
            && initial_stop.exception_code == STATUS_BREAKPOINT
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
            last_stop_was_managed_breakpoint: false,
            reconnect_assist_after_continue: None,
            special_register_cache: HashMap::new(),
            exit_prepared: false,
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            translations: Arc::new(TranslationCache::default()),
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
        self.link.framing()
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
        let join = std::thread::spawn(move || {
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
        self.processor_count = self.processor_count.max(stop.number_processors.max(1));
        self.last_stop_processor = stop.processor;
        self.last_exception_code = stop.exception_code;
        self.last_rip = stop.program_counter;
        self.last_stop_was_managed_breakpoint = managed_breakpoint_stop;
        self.special_register_cache.clear();
        self.link.set_inline_running(false);
    }

    fn record_running(&mut self) {
        self.link.set_inline_running(true);
        self.special_register_cache.clear();
        self.translations.resume();
    }

    fn context_flags(&self) -> u32 {
        match self.arch {
            Arch::Amd64 => context::CONTEXT_ALL,
            Arch::Arm64 => context_arm64::CONTEXT_ALL,
        }
    }

    fn advance_pc_past_breakpoint(&mut self, processor: u16) -> Result<()> {
        self.require_no_pending_write_breakpoint()?;
        let arch = self.arch;
        let framing = self.link.framing()?;
        advance_pc_past_breakpoint(framing, &self.register_map, arch, processor)
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

    fn rollback_dr_slot_states(
        &mut self,
        slot: u8,
        states: &[(u16, DebugRegisterSlotState)],
    ) -> Result<()> {
        let mut first_error = None;
        for &(processor, state) in states.iter().rev() {
            self.current_processor = processor;
            if let Err(error) = self.apply_dr_restore(slot, state)
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

    /// Apply one DR-slot update to every processor as a transaction. The slot's
    /// prior address and DR7 are captured before each write; any read/write
    /// failure restores every processor that may have been modified, including
    /// the one whose reply was lost. The caller's selected processor is always
    /// restored.
    fn update_dr_slot_on_all_processors(
        &mut self,
        slot: u8,
        operation: &str,
        mut update: impl FnMut(&mut Self) -> Result<()>,
    ) -> Result<()> {
        if slot >= HW_BREAKPOINT_SLOTS {
            return Err(Error::Kd(format!(
                "invalid hardware breakpoint slot {slot} (expected 0-{max})",
                max = HW_BREAKPOINT_SLOTS - 1
            )));
        }

        let saved = self.current_processor;
        let result = (|| {
            let mut applied = Vec::with_capacity(self.processor_count.max(1) as usize);
            let mut failure = None;

            for processor in 0..self.processor_count.max(1) {
                self.current_processor = processor;
                let previous = match self.read_dr_slot_state(slot) {
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
            match self.rollback_dr_slot_states(slot, &applied) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(Error::Kd(format!(
                    "hardware breakpoint {operation} failed: {error}; rollback also failed: {rollback_error}"
                ))),
            }
        })();
        self.current_processor = saved;
        result
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
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_control_space(
                framing,
                processor,
                AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
                KSPECIAL_REGISTERS_MIN_SIZE as u32,
            )
        })
    }

    fn write_special_registers(&mut self, special: Vec<u8>) -> Result<()> {
        let processor = self.current_processor;
        let actual = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::write_control_space(
                framing,
                processor,
                AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
                &special,
            )
        })?;
        if actual as usize != special.len() {
            return Err(Error::Kd(format!(
                "short KSPECIAL_REGISTERS write on processor {}: wrote {} of {} bytes",
                processor + 1,
                actual,
                special.len()
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

    fn append_control_registers(&mut self, ctx: &mut Vec<u8>) -> Result<()> {
        match self.arch {
            Arch::Amd64 => {
                let special = self.read_special_registers()?;
                append_control_registers_from_special(ctx, special)
            }
            Arch::Arm64 => {
                // The ARM64 CONTEXT carries no TTBR; fill the synthetic `cr3`
                // slot (TTBR1_EL1) from guest discovery.
                ctx.resize(context_arm64::REGISTER_BUFFER_SIZE, 0);
                ctx[context_arm64::OFFSET_CR3..context_arm64::OFFSET_CR3 + 8]
                    .copy_from_slice(&self.kernel_dtb_override.to_le_bytes());
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
        if should_advance_pc_before_continue(
            self.last_exception_code,
            self.last_stop_was_managed_breakpoint,
        ) {
            self.advance_pc_past_breakpoint(processor)?;
        }
        self.continue_preserving_dr7(processor, api::DBG_CONTINUE, false)?;
        self.record_running();
        Ok(())
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

    /// Convert a connected KD backend into synchronized debugger and physical
    /// memory handles after target hints have been collected.
    pub fn into_remote_memory(self) -> (KdBackendHandle, KdMemory) {
        eprintln!(
            "{}",
            format!(
                "{}: memory source kd; remote reads may be slow.",
                self.backend_name
            )
            .bright_black()
        );
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
            return Err(Error::Kd(
                "KD remote memory requires a halted target; interrupt it before reading memory"
                    .into(),
            ));
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

    fn write_physical_bytes(&mut self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        // The write may land in a page table.
        self.translations.clear();
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

    /// Kernel space under the kernel root is what the target itself maps, so
    /// `DbgKdReadVirtualMemoryApi` resolves it in one request per chunk
    /// where the host walk costs four page-table reads per page first.
    /// Process roots keep the walk: the API has no address-space selector.
    fn read_virtual_direct(
        &mut self,
        addr: VirtAddr,
        root: Dtb,
        buf: &mut [u8],
    ) -> Option<Result<()>> {
        let kernel_space = match self.arch {
            Arch::Amd64 => addr.0 >> 63 != 0,
            Arch::Arm64 => addr.0 & (1 << 55) != 0,
        };
        if !kernel_space || self.kernel_dtb_override == 0 || root != self.kernel_dtb_override {
            return None;
        }
        Some(self.read_virtual_bytes(addr, buf))
    }

    fn read_virtual_bytes(&mut self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        self.require_remote_memory_stopped()?;
        let processor = self.current_processor;
        let mut completed = 0usize;
        while completed < buf.len() {
            let chunk_addr = addr
                .0
                .checked_add(completed as u64)
                .ok_or_else(|| Error::Kd("virtual-memory read address overflow".into()))?;
            // A page is mapped or not as a whole; chunks that stay inside one
            // page make a refused chunk exactly the hole a page walk reports.
            let to_page_end = PAGE_SIZE - (chunk_addr as usize & (PAGE_SIZE - 1));
            let requested = (buf.len() - completed)
                .min(KD_REMOTE_MEMORY_CHUNK)
                .min(to_page_end);
            let data =
                match with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::read_virtual_memory(framing, processor, chunk_addr, requested as u32)
                }) {
                    Ok(data) => data,
                    Err(Error::KdStatus { .. }) if completed > 0 => {
                        return Err(Error::PartialRead(completed));
                    }
                    Err(Error::KdStatus { .. }) => {
                        return Err(Error::BadVirtualAddress(VirtAddr(chunk_addr)));
                    }
                    Err(error) => return Err(error),
                };
            let end = completed + data.len();
            buf[completed..end].copy_from_slice(&data);
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

    fn read_registers(&mut self) -> Result<Vec<u8>> {
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
        kd_trace!("kd: read_registers: extended to {} bytes", ctx.len());
        if trace_enabled() {
            let cr3 = self.register_map.read_u64("cr3", &ctx).unwrap_or(0);
            let pc = self.register_map.read_u64("pc", &ctx).unwrap_or(0);
            let sp = self.register_map.read_u64("sp", &ctx).unwrap_or(0);
            kd_trace!("kd: read_registers: cr3={cr3:#x} pc={pc:#x} sp={sp:#x}");
        }
        Ok(ctx)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        let processor = self.current_processor;
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
                })
            }
        }
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.complete_pending_write_breakpoint(addr)? {
            return Ok(());
        }

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
            Err(err) => return Err(err),
        };
        self.bp_handles.insert(addr, handle);
        self.managed_bp_addresses.insert(addr);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let handle = self
            .bp_handles
            .remove(&addr)
            .ok_or_else(|| Error::Kd(format!("no breakpoint tracked at {addr:#x}")))?;
        self.managed_bp_addresses.remove(&addr);
        let processor = self.current_processor;
        let result = with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::restore_breakpoint(framing, processor, handle)
        });
        if let Err(Error::KdStatus { ntstatus, api }) = &result
            && *ntstatus == STATUS_UNSUCCESSFUL
            && *api == api::DBGKD_RESTORE_BREAKPOINT
        {
            kd_trace!(
                "kd: restore breakpoint handle {} at {:#x} was already consumed",
                handle,
                addr
            );
            return Ok(());
        }
        result
    }

    fn supports_watchpoints(&self) -> bool {
        // AArch64 has no x86-style debug registers; hardware watchpoints would
        // need DBGWCR/DBGWVR support in the KD transport.
        self.arch == Arch::Amd64
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
        // DR state is per-processor, so program every CPU: watched code can run
        // anywhere. The shared transaction prevents an untracked partial set.
        self.update_dr_slot_on_all_processors(slot, "install", |backend| {
            backend.apply_dr_set(slot, addr, access, len)
        })
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        // A failed disable/remove must leave the manager's still-enabled entry
        // truthful, so clearing receives the same rollback guarantee as set.
        self.update_dr_slot_on_all_processors(slot, "clear", |backend| backend.apply_dr_clear(slot))
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        // GuestMemoryPatch user-mode breakpoints write an x86 `int3`; the
        // AArch64 equivalent (4-byte `brk #0xF000`) is not wired up yet.
        self.arch == Arch::Amd64
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
        ]
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.debug_log.read_since(since_seq)
    }

    fn note_breakpoint_installed(&mut self, addr: u64) {
        self.managed_bp_addresses.insert(addr);
    }

    fn note_breakpoint_uninstalled(&mut self, addr: u64) {
        self.managed_bp_addresses.remove(&addr);
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
        if should_advance_pc_before_continue(
            self.last_exception_code,
            self.last_stop_was_managed_breakpoint,
        ) {
            kd_trace!(
                "kd: continue: advancing p{} RIP past raw int3 (last_exception_code={:#x})",
                resume_processor + 1,
                self.last_exception_code,
            );
            self.advance_pc_past_breakpoint(resume_processor)?;
        } else {
            kd_trace!(
                "kd: continue: not advancing p{} (last_exception_code={:#x}, managed_bp={})",
                resume_processor + 1,
                self.last_exception_code,
                self.last_stop_was_managed_breakpoint
            );
        }
        // The pump absorbs the re-break a stale break-in byte causes right
        // after resume; it needs to know where we resumed from and which
        // breakpoints are real. Nothing can change either while the VM runs.
        let drain = ContinueDrain::new(
            self.last_rip,
            resume_processor,
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
        if processor == self.last_stop_processor
            && should_advance_pc_before_continue(
                self.last_exception_code,
                self.last_stop_was_managed_breakpoint,
            )
        {
            self.advance_pc_past_breakpoint(processor)?;
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
        // Blocking wait: give the socket a timeout long enough to be a block
        // (the request paths leave their shorter timeouts in place, and the

        // restore-to-none setsockopt is macOS-racy).
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
        // The background pump caught a state-change, reported it into its
        // channel, and exited, but no foreground wait has consumed it yet, so
        // `is_running` still holds its stale post-continue `true`. The VM is
        // actually halted.
        matches!(&self.link, Link::RunningPumped(pump) if pump.reported_stop.load(Ordering::SeqCst))
    }

    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        let result = self.finish_for_exit(leave_running);
        if result.is_ok() {
            self.exit_prepared = true;
        }
        result
    }

    fn take_modules_changed(&mut self) -> bool {
        // the flag rides back on the framing when the pump reclaims it at a stop
        self.link
            .framing()
            .map(KdFraming::take_modules_changed)
            .unwrap_or(false)
    }
}

impl DebugBackend for KdBackendHandle {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
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

    fn optional_capabilities(&self) -> Vec<BackendCapability> {
        self.lock().optional_capabilities()
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.lock().read_debug_output(since_seq)
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

    fn take_modules_changed(&mut self) -> bool {
        self.lock().take_modules_changed()
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
mod tests {
    use super::*;
    use crate::guest::{Guest, WinObject};
    use crate::kd::framing::{
        PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_FILE_IO,
        PACKET_TYPE_KD_RESET, PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_STATE_MANIPULATE,
    };
    use crate::phys::PhysMem;
    use crate::symbols::{FieldInfo, ParsedType, SymbolStore, TypeInfo};
    use std::io::{Cursor, Read, Write};
    use std::time::Instant;

    #[test]
    fn kd_detects_amd64_and_arm64_machine_types() {
        assert_eq!(detect_arch(0x8664).unwrap(), Arch::Amd64);
        assert_eq!(detect_arch(0xaa64).unwrap(), Arch::Arm64);
        let error = detect_arch(0x014c).unwrap_err();
        assert!(error.to_string().contains("I386 KD target"));
    }

    #[test]
    fn kd_memory_source_parses_supported_values() {
        assert_eq!("auto".parse(), Ok(KdMemorySource::Auto));
        assert_eq!("host".parse(), Ok(KdMemorySource::Host));
        assert_eq!("kd".parse(), Ok(KdMemorySource::Kd));
        assert!("remote".parse::<KdMemorySource>().is_err());
    }

    #[test]
    fn arm64_ttbr1_normalizes_to_combined_page_table_page() {
        // Windows commonly places TTBR0 and TTBR1 in the lower/upper 0x800
        // halves of one page. Strip both that offset and the full 16-bit ASID.
        assert_eq!(
            normalize_kernel_dtb(Arch::Arm64, 0x004f_0000_80d4_5800),
            0x80d4_5000
        );
    }

    #[test]
    fn arm64_target_hints_read_ttbr1_through_kd() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.arch = Arch::Arm64;
        backend.register_map = context_arm64::build_register_map();
        backend.link.set_inline_running(false);
        backend.exit_prepared = true;
        let kernel_base = 0xffff_f802_4e80_0000u64;
        let module_list = 0xffff_f802_4f4d_aed0u64;

        let worker = std::thread::spawn(move || {
            let version_request = read_wire_packet(&mut kernel);
            let version_id = u32::from_le_bytes(version_request[8..12].try_into().unwrap());
            assert_eq!(
                u32::from_le_bytes(version_request[16..20].try_into().unwrap()),
                api::DBGKD_GET_VERSION
            );
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, version_id))
                .unwrap();
            let mut version_union = [0u8; 40];
            version_union[8..10].copy_from_slice(&0xaa64u16.to_le_bytes());
            version_union[16..24].copy_from_slice(&kernel_base.to_le_bytes());
            version_union[24..32].copy_from_slice(&module_list.to_le_bytes());
            let version_reply = manipulate_reply_payload(api::DBGKD_GET_VERSION, 0, &version_union);
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    WIRE_FIRST_PACKET_ID,
                    &version_reply,
                ))
                .unwrap();
            let _version_ack = read_wire_packet(&mut kernel);

            let ttbr_request = read_wire_packet(&mut kernel);
            let ttbr_id = u32::from_le_bytes(ttbr_request[8..12].try_into().unwrap());
            assert_eq!(
                u32::from_le_bytes(ttbr_request[16..20].try_into().unwrap()),
                api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER
            );
            assert_eq!(
                u32::from_le_bytes(ttbr_request[32..36].try_into().unwrap()),
                ARM64_WINDBG_TTBR1_EL1
            );
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, ttbr_id))
                .unwrap();
            let ttbr = 0x0040_0000_80d4_5800u64;
            let mut ttbr_union = [0u8; 12];
            ttbr_union[0..4].copy_from_slice(&ARM64_WINDBG_TTBR1_EL1.to_le_bytes());
            ttbr_union[4..8].copy_from_slice(&(ttbr as u32).to_le_bytes());
            ttbr_union[8..12].copy_from_slice(&((ttbr >> 32) as u32).to_le_bytes());
            let ttbr_reply =
                manipulate_reply_payload(api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER, 0, &ttbr_union);
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    WIRE_FIRST_PACKET_ID ^ 1,
                    &ttbr_reply,
                ))
                .unwrap();
            let _ttbr_ack = read_wire_packet(&mut kernel);
        });

        let hints = backend.target_hints().unwrap();

        worker.join().unwrap();
        assert_eq!(hints.arch, Arch::Arm64);
        assert_eq!(hints.kernel_dtb, 0x80d4_5000);
        assert_eq!(hints.kernel_base, VirtAddr(kernel_base));
        assert_eq!(hints.ps_loaded_module_list, VirtAddr(module_list));
    }

    #[test]
    fn transparent_arm64_state_change_uses_arm64_continue_layout() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let stop = StateChange {
            processor: 2,
            number_processors: 4,
            new_state: DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
            exception_code: 0,
            exception_first_chance: None,
            exception_address: None,
            program_counter: 0xffff_f800_1234_5678,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: false,
        };
        let handle = std::thread::spawn(move || {
            let mut framing = KdFraming::new(host.into());
            continue_transparent_state_change(&mut framing, Arch::Arm64, &stop)
        });

        let packet = read_wire_packet(&mut kernel);
        let packet_id = u32::from_le_bytes(packet[8..12].try_into().unwrap());
        let request = &packet[WIRE_HEADER_SIZE..];
        assert_eq!(
            u32::from_le_bytes(request[0..4].try_into().unwrap()),
            api::DBGKD_CONTINUE_API2
        );
        assert_eq!(
            u32::from_le_bytes(request[16..20].try_into().unwrap()),
            api::DBG_CONTINUE
        );
        assert_eq!(&request[20..24], &[0; 4]);
        assert_eq!(&request[24..40], &[0; 16]);

        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
            .unwrap();
        kernel.flush().unwrap();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn arm64_capabilities_exclude_amd64_only_breakpoints() {
        let (_kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.arch = Arch::Arm64;

        for capability in [
            DebugCapability::UserModeBreakpoints,
            DebugCapability::Watchpoints,
        ] {
            assert!(
                backend
                    .capabilities()
                    .iter()
                    .any(|entry| { entry.capability == capability && !entry.supported })
            );
        }
        assert!(matches!(
            backend.set_hardware_breakpoint(0, 0x1000, HwBreakpointAccess::Write, 4),
            Err(Error::NotSupported)
        ));
    }

    struct Loopback {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Loopback {
        fn new() -> Self {
            Self {
                inbound: Cursor::new(Vec::new()),
                outbound: Vec::new(),
            }
        }

        fn with_inbound(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            Read::read(&mut self.inbound, buf)
        }
    }

    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn debug_io_print_payload(text: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; DBGKD_DEBUG_IO_HEADER_SIZE];
        payload[0..4].copy_from_slice(&DBGKD_PRINT_STRING_API.to_le_bytes());
        payload[8..12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        payload.extend_from_slice(text);
        payload
    }

    #[test]
    fn parse_state_change_extracts_processor_and_pc() {
        let mut payload = vec![0u8; 64];
        payload[0..4].copy_from_slice(&DBG_KD_EXCEPTION_STATE_CHANGE.to_le_bytes()); // NewState
        payload[6..8].copy_from_slice(&2u16.to_le_bytes()); // Processor = 2
        payload[8..12].copy_from_slice(&4u32.to_le_bytes()); // NumberProcessors
        payload[24..32].copy_from_slice(&0xfffff800deadbeefu64.to_le_bytes());
        payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());

        let s = parse_state_change(&payload).unwrap();
        assert_eq!(s.processor, 2);
        assert_eq!(s.number_processors, 4);
        assert_eq!(s.new_state, DBG_KD_EXCEPTION_STATE_CHANGE);
        assert_eq!(s.exception_code, STATUS_BREAKPOINT);
        assert_eq!(s.program_counter, 0xfffff800deadbeef);
    }

    #[test]
    fn parse_state_change_extracts_exception_record_metadata() {
        let mut payload = vec![0u8; 188];
        payload[0..4].copy_from_slice(&DBG_KD_EXCEPTION_STATE_CHANGE.to_le_bytes());
        payload[32..36].copy_from_slice(&0xc000_0005u32.to_le_bytes());
        payload[48..56].copy_from_slice(&0xfffff800_12345678u64.to_le_bytes());
        payload[184..188].copy_from_slice(&1u32.to_le_bytes());

        let first = parse_state_change(&payload).unwrap();
        assert_eq!(first.exception_address, Some(0xfffff800_12345678));
        assert_eq!(first.exception_first_chance, Some(true));

        payload[184..188].copy_from_slice(&0u32.to_le_bytes());
        let second = parse_state_change(&payload).unwrap();
        assert_eq!(second.exception_first_chance, Some(false));
    }

    #[test]
    fn parse_load_symbols_state_change_extracts_base_hint() {
        let mut payload = vec![0u8; 64];
        payload[0..4].copy_from_slice(&DBG_KD_LOAD_SYMBOLS_STATE_CHANGE.to_le_bytes());
        payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        payload[24..32].copy_from_slice(&0xfffff800004f9325u64.to_le_bytes());
        payload[40..48].copy_from_slice(&0xfffff80000000000u64.to_le_bytes());

        let s = parse_state_change(&payload).unwrap();

        assert_eq!(s.program_counter, 0xfffff800004f9325);
        assert_eq!(s.kernel_base_hint, Some(VirtAddr(0xfffff80000000000)));
    }

    #[test]
    fn stop_event_preserves_kd_exception_details() {
        let stop = StateChange {
            processor: 1,
            number_processors: 2,
            new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
            exception_code: STATUS_BREAKPOINT,
            exception_first_chance: Some(true),
            exception_address: Some(0xfffff800deadbeef),
            program_counter: 0xfffff800deadbeef,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: false,
        };

        let event = stop_event(stop);
        assert_eq!(event.thread_id.as_deref(), Some("p1.2"));
        assert_eq!(event.exception_code, Some(STATUS_BREAKPOINT));
        assert_eq!(event.first_chance, Some(true));
        assert_eq!(event.exception_address, Some(0xfffff800deadbeef));
        assert_eq!(event.program_counter, Some(0xfffff800deadbeef));
        assert_eq!(event.target_kernel_base_hint, None);
        assert!(!event.is_bugcheck);
        assert!(event.bugcheck.is_none());
        assert!(!event.target_reloaded);
        assert!(!event.assisted_breakin);
    }

    #[test]
    fn stop_event_preserves_target_reload_flag() {
        let stop = StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
            exception_code: STATUS_BREAKPOINT,
            exception_first_chance: Some(true),
            exception_address: Some(0xfffff800deadbeef),
            program_counter: 0xfffff800deadbeef,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: true,
            assisted_breakin: false,
        };

        let event = stop_event(stop);
        assert!(event.target_reloaded);
        assert!(!event.is_bugcheck);
    }

    #[test]
    fn stop_event_preserves_assisted_breakin_flag() {
        let stop = StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
            exception_code: STATUS_BREAKPOINT,
            exception_first_chance: Some(true),
            exception_address: Some(0xfffff800deadbeef),
            program_counter: 0xfffff800deadbeef,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: true,
        };

        let event = stop_event(stop);
        assert!(event.assisted_breakin);
    }

    #[test]
    fn stop_event_flags_surfaced_load_symbols_as_bugcheck() {
        let stop = StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
            exception_code: 0,
            exception_first_chance: None,
            exception_address: None,
            program_counter: 0xfffff8007faf9325,
            kernel_base_hint: Some(VirtAddr(0xfffff8007f600000)),
            is_bugcheck: true,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: false,
        };

        let event = stop_event(stop);
        assert!(event.is_bugcheck);
        assert_eq!(event.exception_code, None);
        assert_eq!(event.program_counter, Some(0xfffff8007faf9325));
        assert_eq!(
            event.target_kernel_base_hint,
            Some(VirtAddr(0xfffff8007f600000))
        );
        assert!(event.bugcheck.is_none());
    }

    #[test]
    fn stop_event_does_not_flag_reloaded_load_symbols_as_bugcheck() {
        let stop = StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
            exception_code: 0,
            exception_first_chance: None,
            exception_address: None,
            program_counter: 0xfffff8007faf9325,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: true,
            assisted_breakin: false,
        };

        let event = stop_event(stop);
        assert!(event.target_reloaded);
        assert!(!event.is_bugcheck);
        assert_eq!(event.exception_code, None);
    }

    #[test]
    fn bugcheck_capture_extracts_fatal_error_and_driver() {
        let mut capture = BugcheckCapture::default();
        capture.observe_debug_text(
            b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0xFFFFB90641184010,0x0000000000000002,0x0000000000000000,0xFFFFF8016E151730)\r\n",
        );
        capture.observe_debug_text(b"Driver at fault: myfault.sys.\r\n");

        let info = capture.finish().unwrap();
        assert_eq!(info.code, 0xd1);
        assert_eq!(
            info.parameters,
            [
                0xffff_b906_4118_4010,
                0x0000_0000_0000_0002,
                0x0000_0000_0000_0000,
                0xffff_f801_6e15_1730,
            ]
        );
        assert_eq!(info.driver.as_deref(), Some("myfault.sys"));
    }

    #[test]
    fn captured_bugcheck_debug_io_can_be_suppressed() {
        let payload = debug_io_print_payload(
            b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0x1,0x2,0x0,0x4)\r\n",
        );
        let mut framing = KdFraming::new(Loopback::new());
        let mut capture = BugcheckCapture::default();
        let mut output = Vec::new();
        let debug_log = DebugLog::new(DEBUG_LOG_CAPACITY);

        let saw_refresh = handle_debug_io_with_output(
            &mut framing,
            &payload,
            true,
            Some(&mut capture),
            true,
            Some(&debug_log),
            &mut output,
        )
        .unwrap();

        assert!(!saw_refresh);
        assert!(output.is_empty());
        assert_eq!(capture.finish().unwrap().code, 0xd1);
        // The terminal stream is suppressed during a bugcheck, but the ring is
        // the complete record and still captures the crash text.
        let page = debug_log.read_since(0);
        assert!(
            page.lines
                .iter()
                .any(|line| line.text.contains("Fatal System Error"))
        );
    }

    #[test]
    fn parse_debug_io_print_extracts_string() {
        let payload = debug_io_print_payload(b"hello");

        match parse_debug_io(&payload).unwrap() {
            DebugIo::PrintString { text } => assert_eq!(text, b"hello"),
            DebugIo::GetString { .. } => panic!("expected print-string debug I/O"),
        }
    }

    #[test]
    fn debug_io_refresh_message_is_reported_when_waiting_for_stop() {
        let payload = debug_io_print_payload(b"KDTARGET: Refreshing KD connection\n");
        let mut framing = KdFraming::new(Loopback::new());
        let mut output = Vec::new();

        let saw_refresh = handle_debug_io_with_output(
            &mut framing,
            &payload,
            true,
            None,
            false,
            None,
            &mut output,
        )
        .unwrap();

        assert!(saw_refresh);
        assert_eq!(output, b"KDTARGET: Refreshing KD connection\n");
        assert!(framing.transport_ref().outbound.is_empty());
    }

    #[test]
    fn debug_io_refresh_message_is_passive_during_manipulate_requests() {
        let payload = debug_io_print_payload(b"KDTARGET: Refreshing KD connection\n");
        let mut framing = KdFraming::new(Loopback::new());
        let mut output = Vec::new();

        let saw_refresh = handle_debug_io_with_output(
            &mut framing,
            &payload,
            false,
            None,
            false,
            None,
            &mut output,
        )
        .unwrap();

        assert!(!saw_refresh);
        assert_eq!(output, b"KDTARGET: Refreshing KD connection\n");
        assert!(framing.transport_ref().outbound.is_empty());
    }

    #[test]
    fn parse_debug_io_print_accepts_legacy_short_header() {
        let mut payload = vec![0u8; DBGKD_DEBUG_IO_MIN_HEADER_SIZE];
        payload[0..4].copy_from_slice(&DBGKD_PRINT_STRING_API.to_le_bytes());
        payload[8..12].copy_from_slice(&5u32.to_le_bytes());
        payload.extend_from_slice(b"hello");

        match parse_debug_io(&payload).unwrap() {
            DebugIo::PrintString { text } => assert_eq!(text, b"hello"),
            DebugIo::GetString { .. } => panic!("expected print-string debug I/O"),
        }
    }

    #[test]
    fn parse_debug_io_get_string_reads_full_header() {
        let mut payload = vec![0u8; DBGKD_DEBUG_IO_HEADER_SIZE];
        payload[0..4].copy_from_slice(&DBGKD_GET_STRING_API.to_le_bytes());
        payload[4..6].copy_from_slice(&0x33u16.to_le_bytes());
        payload[6..8].copy_from_slice(&2u16.to_le_bytes());
        payload[8..12].copy_from_slice(&7u32.to_le_bytes());
        payload[12..16].copy_from_slice(&0x100u32.to_le_bytes());
        payload.extend_from_slice(b"prompt>");

        match parse_debug_io(&payload).unwrap() {
            DebugIo::GetString {
                processor_level,
                processor,
                prompt,
            } => {
                assert_eq!(processor_level, 0x33);
                assert_eq!(processor, 2);
                assert_eq!(prompt, b"prompt>");
            }
            DebugIo::PrintString { .. } => panic!("expected get-string debug I/O"),
        }
    }

    #[test]
    fn parse_debug_io_print_rejects_other_api() {
        let mut payload = vec![0u8; DBGKD_DEBUG_IO_MIN_HEADER_SIZE];
        payload[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        assert!(parse_debug_io(&payload).is_none());
    }

    #[test]
    fn parse_state_change_rejects_short_payload() {
        let err = parse_state_change(&[0u8; 10]).unwrap_err();
        match err {
            Error::Kd(msg) => assert!(msg.contains("too short")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn continue_advance_policy_skips_only_unmanaged_software_breakpoints() {
        assert!(should_advance_pc_before_continue(STATUS_BREAKPOINT, false));
        assert!(!should_advance_pc_before_continue(STATUS_BREAKPOINT, true));
        assert!(!should_advance_pc_before_continue(0x8000_0004, false)); // STATUS_SINGLE_STEP
    }

    #[test]
    fn initial_handshake_breaks_in_immediately_then_resets() {
        assert_eq!(
            initial_handshake_stimulus(0),
            InitialHandshakeStimulus::BreakIn
        );
        assert_eq!(
            initial_handshake_stimulus(1),
            InitialHandshakeStimulus::Reset
        );
        assert_eq!(
            initial_handshake_stimulus(2),
            InitialHandshakeStimulus::BreakIn
        );
        assert_eq!(
            initial_handshake_stimulus(3),
            InitialHandshakeStimulus::Reset
        );
    }

    #[test]
    fn kd_initial_timeout_defaults_to_eight_seconds() {
        assert_eq!(
            parse_kd_initial_timeout(None).unwrap(),
            Duration::from_secs(8)
        );
    }

    #[test]
    fn kd_initial_timeout_accepts_positive_seconds() {
        assert_eq!(
            parse_kd_initial_timeout(Some("12")).unwrap(),
            Duration::from_secs(12)
        );
    }

    #[test]
    fn kd_initial_timeout_rejects_invalid_values() {
        assert!(parse_kd_initial_timeout(Some("0")).is_err());
        assert!(parse_kd_initial_timeout(Some("meow")).is_err());
    }

    #[test]
    fn context_payload_accepts_synthetic_register_buffer() {
        let synthetic = vec![0u8; context::REGISTER_BUFFER_SIZE];
        assert_eq!(
            context_payload(&synthetic).unwrap().len(),
            context::CONTEXT_SIZE
        );
    }

    #[test]
    fn context_payload_rejects_short_buffers() {
        let short = vec![0u8; context::CONTEXT_SIZE - 1];
        assert!(context_payload(&short).is_err());
    }

    #[test]
    fn append_control_registers_extends_context() {
        let mut ctx = vec![0u8; context::CONTEXT_SIZE];
        let mut special = vec![0u8; KSPECIAL_REGISTERS_MIN_SIZE];
        special[KSPECIAL_REGISTERS_CR0_OFFSET..KSPECIAL_REGISTERS_CR0_OFFSET + 8]
            .copy_from_slice(&0x8005_0033u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR2_OFFSET..KSPECIAL_REGISTERS_CR2_OFFSET + 8]
            .copy_from_slice(&0x1111_2222u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR3_OFFSET..KSPECIAL_REGISTERS_CR3_OFFSET + 8]
            .copy_from_slice(&0x1234_5000u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR4_OFFSET..KSPECIAL_REGISTERS_CR4_OFFSET + 8]
            .copy_from_slice(&0x350ef8u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_CR8_OFFSET..KSPECIAL_REGISTERS_CR8_OFFSET + 8]
            .copy_from_slice(&2u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_DR0_OFFSET..KSPECIAL_REGISTERS_DR0_OFFSET + 8]
            .copy_from_slice(&0xffff_f804_1234_5678u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_DR6_OFFSET..KSPECIAL_REGISTERS_DR6_OFFSET + 8]
            .copy_from_slice(&5u64.to_le_bytes());
        special[KSPECIAL_REGISTERS_DR7_OFFSET..KSPECIAL_REGISTERS_DR7_OFFSET + 8]
            .copy_from_slice(&0x402u64.to_le_bytes());

        append_control_registers_from_special(&mut ctx, &special).unwrap();
        let map = context::build_register_map();

        assert_eq!(ctx.len(), context::REGISTER_BUFFER_SIZE);
        assert_eq!(map.read_u64("cr0", &ctx).unwrap(), 0x8005_0033);
        assert_eq!(map.read_u64("cr2", &ctx).unwrap(), 0x1111_2222);
        assert_eq!(map.read_u64("cr3", &ctx).unwrap(), 0x1234_5000);
        assert_eq!(map.read_u64("cr4", &ctx).unwrap(), 0x350ef8);
        assert_eq!(map.read_u64("dr0", &ctx).unwrap(), 0xffff_f804_1234_5678);
        assert_eq!(map.read_u64("dr6", &ctx).unwrap(), 5);
        assert_eq!(map.read_u64("dr7", &ctx).unwrap(), 0x402);
        assert_eq!(map.read_u64("cr8", &ctx).unwrap(), 2);
    }

    #[test]
    fn context_debug_registers_update_special_registers() {
        let mut ctx = vec![0u8; context::REGISTER_BUFFER_SIZE];
        let mut special = vec![0xa5; KSPECIAL_REGISTERS_MIN_SIZE];
        let map = context::build_register_map();
        map.write_u64("dr0", &mut ctx, 0xffff_f804_1234_5678)
            .unwrap();
        map.write_u64("dr6", &mut ctx, 3).unwrap();
        map.write_u64("dr7", &mut ctx, 0xd0402).unwrap();

        update_special_debug_registers_from_context(&mut special, &ctx).unwrap();

        assert_eq!(
            wire::read_u64(&special, KSPECIAL_REGISTERS_DR0_OFFSET),
            0xffff_f804_1234_5678
        );
        assert_eq!(wire::read_u64(&special, KSPECIAL_REGISTERS_DR6_OFFSET), 3);
        assert_eq!(
            wire::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET),
            0xd0402
        );
        assert_eq!(
            wire::read_u64(&special, KSPECIAL_REGISTERS_CR0_OFFSET),
            0xa5a5_a5a5_a5a5_a5a5,
            "non-debug special registers must remain untouched"
        );
    }

    #[test]
    fn thread_id_uses_one_based_hex() {
        assert_eq!(thread_id_for(0), "p1.1");
        assert_eq!(thread_id_for(3), "p1.4");
        assert_eq!(thread_id_for(15), "p1.10");
    }

    #[test]
    fn thread_id_round_trips() {
        for proc in [0u16, 1, 7, 15, 31] {
            let tid = thread_id_for(proc);
            assert_eq!(parse_thread_id(&tid).unwrap(), proc);
        }
    }

    #[test]
    fn parse_thread_id_rejects_garbage() {
        assert!(parse_thread_id("p2.1").is_err()); // wrong pid
        assert!(parse_thread_id("p1.zz").is_err()); // not hex
        assert!(parse_thread_id("garbage").is_err());
        assert!(parse_thread_id("p1.0").is_err()); // zero index reserved
    }

    #[test]
    fn parse_thread_id_for_processor_count_rejects_out_of_range() {
        assert_eq!(parse_thread_id_for_processor_count("p1.4", 4).unwrap(), 3);
        assert!(parse_thread_id_for_processor_count("p1.5", 4).is_err());
    }

    // Wire-format helpers mirroring framing::Header::encode for driving the
    // pump over a real socket pair (the framing constants are module-private)
    const WIRE_DATA_LEADER: u32 = 0x3030_3030;
    const WIRE_CONTROL_LEADER: u32 = 0x6969_6969;
    const WIRE_HEADER_SIZE: usize = 16;
    const WIRE_TRAILER: u8 = 0xAA;
    const WIRE_FIRST_PACKET_ID: u32 = 0x8080_0000;

    fn wire_control_packet(packet_type: u16, packet_id: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&WIRE_CONTROL_LEADER.to_le_bytes());
        pkt.extend_from_slice(&packet_type.to_le_bytes());
        pkt.extend_from_slice(&0u16.to_le_bytes());
        pkt.extend_from_slice(&packet_id.to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt
    }

    fn wire_data_packet(packet_type: u16, packet_id: u32, payload: &[u8]) -> Vec<u8> {
        let checksum = payload.iter().fold(0u32, |a, &b| a.wrapping_add(b as u32));
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&WIRE_DATA_LEADER.to_le_bytes());
        pkt.extend_from_slice(&packet_type.to_le_bytes());
        pkt.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&packet_id.to_le_bytes());
        pkt.extend_from_slice(&checksum.to_le_bytes());
        pkt.extend_from_slice(payload);
        pkt.push(WIRE_TRAILER);
        pkt
    }

    fn read_wire_packet(stream: &mut UnixStream) -> Vec<u8> {
        let mut header = [0u8; WIRE_HEADER_SIZE];
        stream.read_exact(&mut header).unwrap();
        let mut pkt = header.to_vec();
        let leader = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if leader == WIRE_DATA_LEADER {
            let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            let mut rest = vec![0u8; len + 1];
            stream.read_exact(&mut rest).unwrap();
            pkt.extend_from_slice(&rest);
        }
        pkt
    }

    fn state_change_payload(new_state: u32, pc: u64) -> Vec<u8> {
        let mut payload = vec![0u8; 56];
        payload[0..4].copy_from_slice(&new_state.to_le_bytes());
        payload[8..12].copy_from_slice(&1u32.to_le_bytes()); // NumberProcessors
        payload[24..32].copy_from_slice(&pc.to_le_bytes());
        payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());
        payload
    }

    fn exception_state_change_payload(pc: u64) -> Vec<u8> {
        state_change_payload(DBG_KD_EXCEPTION_STATE_CHANGE, pc)
    }

    #[test]
    fn file_io_create_file_gets_explicit_failure_reply() {
        let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
        payload[0..4].copy_from_slice(&DBGKD_CREATE_FILE_API.to_le_bytes());
        let ack = wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, WIRE_FIRST_PACKET_ID);
        let mut framing = KdFraming::new(Loopback::with_inbound(ack));

        handle_file_io(&mut framing, &payload).unwrap();

        let out = &framing.transport_ref().outbound;
        assert_eq!(out.len(), WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE + 1);
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            WIRE_DATA_LEADER
        );
        assert_eq!(
            u16::from_le_bytes(out[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_FILE_IO
        );
        assert_eq!(
            u16::from_le_bytes(out[6..8].try_into().unwrap()) as usize,
            DBGKD_FILE_IO_HEADER_SIZE
        );
        assert_eq!(
            u32::from_le_bytes(out[8..12].try_into().unwrap()),
            WIRE_FIRST_PACKET_ID
        );
        let reply = &out[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE];
        assert_eq!(
            u32::from_le_bytes(reply[0..4].try_into().unwrap()),
            DBGKD_CREATE_FILE_API
        );
        assert_eq!(
            u32::from_le_bytes(reply[4..8].try_into().unwrap()),
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(
            out[WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE],
            WIRE_TRAILER
        );
    }

    fn kd_backend_with_pump(pump: PumpHandle, breakin_clone: UnixStream) -> KdBackend {
        KdBackend {
            link: Link::RunningPumped(pump),
            breakin_clone: breakin_clone.into(),
            backend_name: "kd",
            register_map: context::build_register_map(),
            arch: Arch::Amd64,
            kernel_dtb_override: 0,
            processor_count: 1,
            current_processor: 0,
            last_stop_processor: 0,
            last_exception_code: 0,
            last_rip: 0,
            last_stop_was_managed_breakpoint: false,
            reconnect_assist_after_continue: None,
            bp_handles: HashMap::new(),
            managed_bp_addresses: HashSet::new(),
            breakin_addresses: HashSet::new(),
            pending_write_breakpoint: None,
            special_register_cache: HashMap::new(),
            exit_prepared: false,
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            translations: Arc::new(TranslationCache::default()),
        }
    }

    fn kd_backend_with_framing(host: UnixStream) -> KdBackend {
        let breakin_clone = host.try_clone().unwrap();
        KdBackend {
            // Running inline: a framing-only fixture never enters Drop's resume path.
            link: Link::RunningInline(KdFraming::new(host.into())),
            breakin_clone: breakin_clone.into(),
            backend_name: "kd",
            register_map: context::build_register_map(),
            arch: Arch::Amd64,
            kernel_dtb_override: 0,
            processor_count: 1,
            current_processor: 0,
            last_stop_processor: 0,
            last_exception_code: 0,
            last_rip: 0,
            last_stop_was_managed_breakpoint: false,
            reconnect_assist_after_continue: None,
            bp_handles: HashMap::new(),
            managed_bp_addresses: HashSet::new(),
            breakin_addresses: HashSet::new(),
            pending_write_breakpoint: None,
            special_register_cache: HashMap::new(),
            exit_prepared: false,
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            translations: Arc::new(TranslationCache::default()),
        }
    }

    fn write_breakpoint_reply_payload(processor: u16, addr: u64, handle: u32) -> Vec<u8> {
        const MANIPULATE_UNION_OFFSET: usize = 16;

        let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
        payload[0..4].copy_from_slice(&api::DBGKD_WRITE_BREAKPOINT.to_le_bytes());
        payload[6..8].copy_from_slice(&processor.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
            .copy_from_slice(&addr.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
            .copy_from_slice(&handle.to_le_bytes());
        payload
    }

    fn manipulate_reply_payload(api_number: u32, processor: u16, union_body: &[u8]) -> Vec<u8> {
        const MANIPULATE_UNION_OFFSET: usize = 16;

        let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
        payload[0..4].copy_from_slice(&api_number.to_le_bytes());
        payload[6..8].copy_from_slice(&processor.to_le_bytes());
        let end = (MANIPULATE_UNION_OFFSET + union_body.len()).min(payload.len());
        payload[MANIPULATE_UNION_OFFSET..end]
            .copy_from_slice(&union_body[..end - MANIPULATE_UNION_OFFSET]);
        payload
    }

    fn physical_memory_reply_payload(processor: u16, addr: u64, data: &[u8]) -> Vec<u8> {
        const MANIPULATE_UNION_OFFSET: usize = 16;

        let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
        payload[0..4].copy_from_slice(&api::DBGKD_READ_PHYSICAL_MEMORY.to_le_bytes());
        payload[6..8].copy_from_slice(&processor.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
            .copy_from_slice(&addr.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
            .copy_from_slice(&(data.len() as u32).to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET + 12..MANIPULATE_UNION_OFFSET + 16]
            .copy_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(data);
        payload
    }

    #[test]
    fn kd_memory_reads_physical_bytes_through_shared_backend() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.link.set_inline_running(false);
        backend.exit_prepared = true;
        let inner = Arc::new(Mutex::new(backend));
        let memory = KdMemory {
            inner: Arc::clone(&inner),
            translations: Arc::new(TranslationCache::default()),
        };
        let expected = [0xde, 0xad, 0xbe, 0xef];

        let worker = std::thread::spawn(move || {
            let request = read_wire_packet(&mut kernel);
            let packet_id = u32::from_le_bytes(request[8..12].try_into().unwrap());
            assert_eq!(
                u32::from_le_bytes(request[16..20].try_into().unwrap()),
                api::DBGKD_READ_PHYSICAL_MEMORY
            );
            assert_eq!(
                u64::from_le_bytes(request[32..40].try_into().unwrap()),
                0x1234_5000
            );
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
                .unwrap();
            let reply = physical_memory_reply_payload(0, 0x1234_5000, &expected);
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    WIRE_FIRST_PACKET_ID,
                    &reply,
                ))
                .unwrap();
            let ack = read_wire_packet(&mut kernel);
            assert_eq!(
                u16::from_le_bytes(ack[4..6].try_into().unwrap()),
                PACKET_TYPE_KD_ACKNOWLEDGE
            );
        });

        let mut actual = [0u8; 4];
        memory.read_bytes(0x1234_5000, &mut actual).unwrap();
        worker.join().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn kd_memory_rejects_reads_while_target_runs() {
        let (_kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.exit_prepared = true;
        let memory = KdMemory {
            inner: Arc::new(Mutex::new(backend)),
            translations: Arc::new(TranslationCache::default()),
        };
        let error = memory.read_bytes(0x1000, &mut [0u8; 8]).unwrap_err();
        assert!(error.to_string().contains("requires a halted target"));
    }

    /// A halted fake kernel serving `DbgKdReadVirtualMemory` from a map of
    /// kernel-space regions until the host hangs up; returns the request
    /// count so tests can assert how many round trips a guest walk costs.
    fn serve_virtual_memory(
        mut kernel: UnixStream,
        regions: Vec<(u64, Vec<u8>)>,
    ) -> std::thread::JoinHandle<usize> {
        const UNION: usize = 16;
        std::thread::spawn(move || {
            let mut kernel_id = WIRE_FIRST_PACKET_ID;
            let mut served = 0usize;
            loop {
                let mut header = [0u8; WIRE_HEADER_SIZE];
                if kernel.read_exact(&mut header).is_err() {
                    return served;
                }
                if u32::from_le_bytes(header[0..4].try_into().unwrap()) != WIRE_DATA_LEADER {
                    continue; // host ACK of our last reply
                }
                let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
                let mut request = vec![0u8; len + 1];
                kernel.read_exact(&mut request).unwrap();
                let host_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
                kernel
                    .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
                    .unwrap();

                let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
                assert_eq!(api_number, api::DBGKD_READ_VIRTUAL_MEMORY);
                let addr = u64::from_le_bytes(request[UNION..UNION + 8].try_into().unwrap());
                let wanted =
                    u32::from_le_bytes(request[UNION + 8..UNION + 12].try_into().unwrap()) as usize;
                served += 1;

                let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
                reply[0..4].copy_from_slice(&api_number.to_le_bytes());
                reply[UNION..UNION + 8].copy_from_slice(&addr.to_le_bytes());
                reply[UNION + 8..UNION + 12].copy_from_slice(&(wanted as u32).to_le_bytes());
                match regions.iter().find_map(|(base, bytes)| {
                    let start = addr.checked_sub(*base)? as usize;
                    bytes.get(start..start + wanted)
                }) {
                    Some(data) => {
                        reply[UNION + 12..UNION + 16]
                            .copy_from_slice(&(data.len() as u32).to_le_bytes());
                        reply.extend_from_slice(data);
                    }
                    None => reply[8..12].copy_from_slice(&0xC000_0005u32.to_le_bytes()),
                }
                kernel
                    .write_all(&wire_data_packet(
                        PACKET_TYPE_KD_STATE_MANIPULATE,
                        kernel_id,
                        &reply,
                    ))
                    .unwrap();
                kernel_id ^= 1;
            }
        })
    }

    const FAKE_KERNEL_DTB: u64 = 0x1ad000;
    const FAKE_KERNEL_BASE: u64 = 0xffff_f800_0000_0000;
    const FAKE_GUID: u128 = 0x51;

    fn field(offset: u32, size: u64, type_data: ParsedType) -> FieldInfo {
        FieldInfo {
            offset,
            size,
            type_data,
        }
    }

    fn primitive(offset: u32, size: u64) -> FieldInfo {
        field(offset, size, ParsedType::Primitive("u".into()))
    }

    fn layout(name: &str, size: usize, fields: &[(&str, FieldInfo)]) -> TypeInfo {
        TypeInfo {
            name: name.to_string(),
            size,
            fields: fields
                .iter()
                .map(|(name, info)| (name.to_string(), info.clone()))
                .collect(),
        }
    }

    /// Build a halted KD-backed guest over `regions` with `types` and
    /// `symbols` standing in for the kernel PDB. The backend is returned so a
    /// test can resume it; the join handle yields the request count.
    fn synthetic_guest(
        regions: Vec<(u64, Vec<u8>)>,
        types: Vec<TypeInfo>,
        symbols: &[(&str, u32)],
    ) -> (Guest, Arc<Mutex<KdBackend>>, std::thread::JoinHandle<usize>) {
        let (kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.link.set_inline_running(false);
        backend.exit_prepared = true;
        backend.kernel_dtb_override = FAKE_KERNEL_DTB;
        let translations = Arc::clone(&backend.translations);
        let inner = Arc::new(Mutex::new(backend));
        let phys = Arc::new(PhysMem::remote(KdMemory {
            inner: Arc::clone(&inner),
            translations,
        }));
        let store = Arc::new(SymbolStore::new());
        store.inject_module_for_test(FAKE_GUID, types, symbols);
        let mut ntoskrnl = WinObject::new_with_arch(
            phys,
            store,
            FAKE_KERNEL_DTB,
            VirtAddr(FAKE_KERNEL_BASE),
            Arch::Amd64,
        );
        ntoskrnl.guid = Some(FAKE_GUID);
        let worker = serve_virtual_memory(kernel, regions);
        (Guest::from_kernel(ntoskrnl), inner, worker)
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn resume_and_halt(backend: &Arc<Mutex<KdBackend>>) {
        let mut backend = backend.lock().unwrap();
        backend.record_running();
        backend.link.set_inline_running(false);
    }

    /// Each `_EPROCESS` costs one request (its field span) and the list is
    /// served from the halt memo until the target runs; short names never
    /// touch the PEB.
    #[test]
    fn process_walk_reads_one_span_per_process_and_memoizes_per_halt() {
        const PID: u32 = 0x440;
        const LINKS: u32 = 0x448;
        const NAME: u32 = 0x5a8;
        const DTB: u32 = 0x28;
        let eprocess = layout(
            "_EPROCESS",
            0x600,
            &[
                (
                    "Pcb",
                    field(0, 0x438, ParsedType::Struct("_KPROCESS".into())),
                ),
                ("UniqueProcessId", primitive(PID, 8)),
                ("ActiveProcessLinks", primitive(LINKS, 16)),
                ("ImageFileName", primitive(NAME, 15)),
            ],
        );
        let kprocess = layout(
            "_KPROCESS",
            0x438,
            &[("DirectoryTableBase", primitive(DTB, 8))],
        );

        let head = FAKE_KERNEL_BASE + 0x1008;
        let system = 0xffff_e000_0001_0000u64;
        let smss = 0xffff_e000_0002_0000u64;
        let mut nt = vec![0u8; 0x2000];
        put_u64(&mut nt, 0x1000, system);
        put_u64(&mut nt, 0x1008, system + LINKS as u64);
        let mut process = |pid: u64, dtb: u64, name: &[u8], next: u64| {
            let mut bytes = vec![0u8; 0x600];
            put_u64(&mut bytes, PID as usize, pid);
            put_u64(&mut bytes, DTB as usize, dtb);
            put_u64(&mut bytes, LINKS as usize, next + LINKS as u64);
            bytes[NAME as usize..NAME as usize + name.len()].copy_from_slice(name);
            bytes
        };
        let regions = vec![
            (FAKE_KERNEL_BASE, nt),
            (system, process(4, 0x1ad000, b"System", smss)),
            (
                smss,
                process(0x1d8, 0x2be000, b"smss.exe", head - LINKS as u64),
            ),
        ];
        let (guest, backend, worker) = synthetic_guest(
            regions,
            vec![eprocess, kprocess],
            &[
                ("PsInitialSystemProcess", 0x1000),
                ("PsActiveProcessHead", 0x1008),
            ],
        );

        let first = guest.enumerate_processes().unwrap();
        let names: Vec<_> = first.iter().map(|p| (p.name.as_str(), p.pid)).collect();
        assert_eq!(names, [("System", 4), ("smss.exe", 0x1d8)]);
        assert_eq!(first[1].dtb, 0x2be000);

        let second = guest.enumerate_processes().unwrap();
        assert_eq!(second.len(), 2);
        let one = guest.process_at(VirtAddr(smss)).unwrap();
        assert_eq!(
            (one.name.as_str(), one.pid, one.dtb),
            ("smss.exe", 0x1d8, 0x2be000)
        );

        resume_and_halt(&backend);
        assert_eq!(guest.enumerate_processes().unwrap().len(), 2);

        drop(guest);
        drop(backend);
        // PsInitialSystemProcess + two spans per walk, one span for
        // `process_at`, and the memoized second walk costs nothing.
        assert_eq!(worker.join().unwrap(), 3 + 1 + 3);
    }

    /// A loader record is prefetched whole, so a module costs the record
    /// image plus its name buffer rather than one request per field.
    #[test]
    fn kernel_module_walk_prefetches_each_record() {
        const DLL_BASE: u32 = 0x30;
        const SIZE: u32 = 0x40;
        const NAME: u32 = 0x58;
        const TIME_DATE_STAMP: u32 = 0x9c;
        const CHECK_SUM: u32 = 0x100;
        let entry = layout(
            "_KLDR_DATA_TABLE_ENTRY",
            0x120,
            &[
                ("InLoadOrderLinks", primitive(0, 16)),
                ("DllBase", primitive(DLL_BASE, 8)),
                ("SizeOfImage", primitive(SIZE, 4)),
                (
                    "BaseDllName",
                    field(NAME, 16, ParsedType::Struct("_UNICODE_STRING".into())),
                ),
                ("TimeDateStamp", primitive(TIME_DATE_STAMP, 4)),
                ("CheckSum", primitive(CHECK_SUM, 4)),
            ],
        );
        let unicode = layout(
            "_UNICODE_STRING",
            16,
            &[("Length", primitive(0, 2)), ("Buffer", primitive(8, 8))],
        );

        let head = FAKE_KERNEL_BASE + 0x2000;
        let names = 0xffff_e000_0009_0000u64;
        let entries = 0xffff_e000_000a_0000u64;
        let mut nt = vec![0u8; 0x3000];
        put_u64(&mut nt, 0x2000, entries);
        let name_bytes: Vec<u8> = "ntoskrnl.exe\0\0\0\0hal.dll"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut records = vec![0u8; 0x240];
        let mut record = |at: usize, next: u64, base: u64, name_off: u64, name_len: u16| {
            put_u64(&mut records, at, next);
            put_u64(&mut records, at + DLL_BASE as usize, base);
            records[at + SIZE as usize..at + SIZE as usize + 4]
                .copy_from_slice(&0x1000u32.to_le_bytes());
            records[at + NAME as usize..at + NAME as usize + 2]
                .copy_from_slice(&name_len.to_le_bytes());
            put_u64(&mut records, at + NAME as usize + 8, names + name_off);
        };
        record(0, entries + 0x120, FAKE_KERNEL_BASE, 0, 24);
        record(0x120, head, 0xffff_f800_1000_0000, 32, 14);
        let regions = vec![
            (FAKE_KERNEL_BASE, nt),
            (names, name_bytes),
            (entries, records),
        ];
        let (guest, backend, worker) = synthetic_guest(
            regions,
            vec![entry, unicode],
            &[("PsLoadedModuleList", 0x2000)],
        );

        let modules = guest.kernel_modules().unwrap();
        let seen: Vec<_> = modules
            .iter()
            .map(|m| (m.name.as_str(), m.base_address.0))
            .collect();
        assert_eq!(
            seen,
            [
                ("ntoskrnl.exe", FAKE_KERNEL_BASE),
                ("hal.dll", 0xffff_f800_1000_0000)
            ]
        );
        assert_eq!(guest.kernel_modules().unwrap().len(), 2);

        drop(guest);
        drop(backend);
        // head pointer + (record image + name buffer) per module
        assert_eq!(worker.join().unwrap(), 1 + 2 * 2);
    }

    fn read_special_registers_reply_payload(processor: u16) -> Vec<u8> {
        const MANIPULATE_UNION_OFFSET: usize = 16;

        let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE + KSPECIAL_REGISTERS_MIN_SIZE];
        payload[0..4].copy_from_slice(&api::DBGKD_READ_CONTROL_SPACE.to_le_bytes());
        payload[6..8].copy_from_slice(&processor.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
            .copy_from_slice(&AMD64_DEBUG_CONTROL_SPACE_KSPECIAL.to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
            .copy_from_slice(&(KSPECIAL_REGISTERS_MIN_SIZE as u32).to_le_bytes());
        payload[MANIPULATE_UNION_OFFSET + 12..MANIPULATE_UNION_OFFSET + 16]
            .copy_from_slice(&(KSPECIAL_REGISTERS_MIN_SIZE as u32).to_le_bytes());
        payload
    }

    #[test]
    fn known_breakin_stop_is_marked_assisted_unless_managed() {
        let (_kernel, host) = UnixStream::pair().unwrap();
        let breakin_clone = host.try_clone().unwrap();
        let pump_host = host.try_clone().unwrap();
        let pump = PumpHandle {
            join: std::thread::spawn(move || KdFraming::new(pump_host.into())),
            stop_rx: mpsc::channel().1,
            shutdown: Arc::new(AtomicBool::new(false)),
            reported_stop: Arc::new(AtomicBool::new(false)),
            breakin_requested: Arc::new(AtomicBool::new(false)),
        };
        let mut backend = kd_backend_with_pump(pump, breakin_clone);
        let pc = 0xfffff800_deadbeef;
        backend.breakin_addresses.insert(pc);

        let stop = StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
            exception_code: STATUS_BREAKPOINT,
            exception_first_chance: Some(true),
            exception_address: Some(pc),
            program_counter: pc,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: false,
        };

        assert!(
            backend
                .mark_known_breakin_stop(stop.clone())
                .assisted_breakin
        );
        backend.managed_bp_addresses.insert(pc);
        assert!(!backend.mark_known_breakin_stop(stop).assisted_breakin);
    }

    #[test]
    fn continue_drains_in_place_rebreak_and_stale_breakin() {
        let resumed_from = 0xffff_f800_0013_40c4;
        let breakin = 0xffff_f800_002f_90d0;
        let drain = |managed: &[u64]| {
            ContinueDrain::new(
                resumed_from,
                0,
                managed.iter().copied().collect(),
                HashSet::from([breakin]),
                context::build_register_map(),
            )
        };

        let stop_at = |code: u32, pc: u64| StateChange {
            processor: 0,
            number_processors: 1,
            new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
            exception_code: code,
            exception_first_chance: Some(true),
            exception_address: Some(pc),
            program_counter: pc,
            kernel_base_hint: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            assisted_breakin: false,
        };

        // Raw int3 re-break at the rip we resumed from: drain it.
        assert!(drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, resumed_from)));
        // Stale break-in byte trapping at the KD break-in instruction: drain it,
        // even though it's nowhere near resumed_from.
        assert!(drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, breakin)));

        // A managed breakpoint hit is a real stop, never drained.
        assert!(!drain(&[breakin]).is_spurious(&stop_at(STATUS_BREAKPOINT, breakin)));

        // An unrelated breakpoint elsewhere, and a single-step, are real stops.
        assert!(!drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, 0xdead_0000)));
        assert!(!drain(&[]).is_spurious(&stop_at(STATUS_SINGLE_STEP, resumed_from)));

        // A break-in the pump itself asked for, and a reload, are never noise.
        let mut assisted = stop_at(STATUS_BREAKPOINT, breakin);
        assisted.assisted_breakin = true;
        assert!(!drain(&[]).is_spurious(&assisted));
        let mut reloaded = stop_at(STATUS_BREAKPOINT, resumed_from);
        reloaded.target_reloaded = true;
        assert!(!drain(&[]).is_spurious(&reloaded));

        // Once the user asked for a break-in, a stop at the break-in
        // instruction is the answer, not noise.
        let interrupted = drain(&[]);
        interrupted.interrupt_flag().store(true, Ordering::SeqCst);
        assert!(!interrupted.is_spurious(&stop_at(STATUS_BREAKPOINT, resumed_from)));
    }

    #[test]
    fn pending_write_breakpoint_retry_completes_late_reply_without_resend() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut backend = kd_backend_with_framing(host);
        let addr = 0xfffff800_12345678;
        let handle = 7;
        backend.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor: 0 });

        let payload = write_breakpoint_reply_payload(0, addr, handle);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                WIRE_FIRST_PACKET_ID,
                &payload,
            ))
            .unwrap();
        kernel.flush().unwrap();

        backend.set_breakpoint(addr).unwrap();

        assert_eq!(backend.bp_handles.get(&addr), Some(&handle));
        assert!(backend.managed_bp_addresses.contains(&addr));
        assert!(backend.pending_write_breakpoint.is_none());

        let ack = read_wire_packet(&mut kernel);
        assert_eq!(
            u32::from_le_bytes(ack[0..4].try_into().unwrap()),
            WIRE_CONTROL_LEADER
        );
        assert_eq!(
            u16::from_le_bytes(ack[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_ACKNOWLEDGE
        );
        assert_eq!(
            u32::from_le_bytes(ack[8..12].try_into().unwrap()),
            WIRE_FIRST_PACKET_ID
        );

        let mut extra = [0u8; 1];
        match kernel.read(&mut extra) {
            Err(e) if is_temporary_io_error(e.kind()) => {}
            Ok(0) => {}
            Ok(n) => panic!("unexpected duplicate KD request: read {n} byte(s)"),
            Err(e) => panic!("unexpected socket read error: {e}"),
        }
    }

    #[test]
    fn pending_write_breakpoint_blocks_unrelated_kd_requests() {
        let (_kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        let addr = 0xfffff800_12345678;
        backend.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor: 0 });

        let err = backend
            .set_breakpoint(addr + 1)
            .expect_err("different breakpoint should be rejected while install is pending");
        let message = err.to_string();
        assert!(message.contains("breakpoint install at 0xfffff80012345678 is pending"));
        assert!(message.contains("retry the same bp command"));

        let err = backend
            .target_kernel_base_hint()
            .expect_err("other KD requests should be rejected while install is pending");
        assert!(err.to_string().contains("retry the same bp command"));
    }

    #[test]
    fn pump_services_state_change_and_returns_framing() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        let pc = 0xfffff800_deadbeef;
        let pkt = wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID,
            &exception_state_change_payload(pc),
        );
        kernel.write_all(&pkt).unwrap();
        kernel.flush().unwrap();

        let stop = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump reported no stop")
            .expect("pump reported an error");
        assert_eq!(stop.program_counter, pc);
        assert_eq!(stop.exception_code, STATUS_BREAKPOINT);

        // Pump exits on its own after reporting the stop, handing back framing
        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn exit_resume_consumes_pump_stop_before_final_continue() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let breakin_clone = host.try_clone().unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let join = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };
        let pump = PumpHandle {
            join,
            stop_rx: rx,
            shutdown,
            reported_stop: Arc::new(AtomicBool::new(false)),
            breakin_requested: Arc::new(AtomicBool::new(false)),
        };
        let mut backend = kd_backend_with_pump(pump, breakin_clone);
        let (continue_tx, continue_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let kernel_thread = std::thread::spawn(move || {
            let pc = 0xfffff800_deadbeef;
            let mut payload = exception_state_change_payload(pc);
            // A plain access violation: exercises the consume-then-continue path
            // without tripping the stray-single-step or int3-advance absorbs,
            // which would issue register reads this mock kernel doesn't service.
            payload[32..36].copy_from_slice(&0xc000_0005u32.to_le_bytes());
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_CHANGE64,
                    WIRE_FIRST_PACKET_ID,
                    &payload,
                ))
                .unwrap();
            kernel.flush().unwrap();

            let ack = read_wire_packet(&mut kernel);
            assert_eq!(
                u32::from_le_bytes(ack[0..4].try_into().unwrap()),
                WIRE_CONTROL_LEADER
            );
            assert_eq!(
                u16::from_le_bytes(ack[4..6].try_into().unwrap()),
                PACKET_TYPE_KD_ACKNOWLEDGE
            );

            let read_special_packet = read_wire_packet(&mut kernel);
            let read_special_request = &read_special_packet
                [WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + api::MANIPULATE_HEADER_SIZE];
            assert_eq!(
                u32::from_le_bytes(read_special_request[0..4].try_into().unwrap()),
                api::DBGKD_READ_CONTROL_SPACE
            );
            let read_special_id =
                u32::from_le_bytes(read_special_packet[8..12].try_into().unwrap());
            kernel
                .write_all(&wire_control_packet(
                    PACKET_TYPE_KD_ACKNOWLEDGE,
                    read_special_id,
                ))
                .unwrap();
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    WIRE_FIRST_PACKET_ID ^ 1,
                    &read_special_registers_reply_payload(0),
                ))
                .unwrap();
            kernel.flush().unwrap();

            let read_special_ack = read_wire_packet(&mut kernel);
            assert_eq!(
                u16::from_le_bytes(read_special_ack[4..6].try_into().unwrap()),
                PACKET_TYPE_KD_ACKNOWLEDGE
            );

            let continue_packet = read_wire_packet(&mut kernel);
            let continue_id = u32::from_le_bytes(continue_packet[8..12].try_into().unwrap());
            continue_tx.send(continue_packet).unwrap();
            kernel
                .write_all(&wire_control_packet(
                    PACKET_TYPE_KD_ACKNOWLEDGE,
                    continue_id,
                ))
                .unwrap();
            kernel.flush().unwrap();
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });

        backend.prepare_for_exit(true).unwrap();
        done_tx.send(()).unwrap();
        kernel_thread.join().expect("kernel thread panicked");
        let continue_packet = continue_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("kernel thread did not capture continue packet");

        assert!(matches!(backend.link, Link::RunningInline(_)));
        assert!(backend.exit_prepared);
        assert_eq!(
            u32::from_le_bytes(continue_packet[0..4].try_into().unwrap()),
            WIRE_DATA_LEADER
        );
        assert_eq!(
            u16::from_le_bytes(continue_packet[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_STATE_MANIPULATE
        );
        let request = &continue_packet[WIRE_HEADER_SIZE..];
        assert_eq!(
            u32::from_le_bytes(request[0..4].try_into().unwrap()),
            api::DBGKD_CONTINUE_API2
        );
        assert_eq!(
            u32::from_le_bytes(request[16..20].try_into().unwrap()),
            api::DBG_CONTINUE
        );
    }

    #[test]
    fn explicit_halted_exit_suppresses_drop_resume() {
        let (host, _kernel) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.link.set_inline_running(false);

        backend.prepare_for_exit(false).unwrap();
        let needs_drop_cleanup = backend.needs_drop_cleanup();
        // Keep unwinding safe if the assertion ever regresses: a running
        // framing-only fixture never enters Drop's resume path.
        backend.link.set_inline_running(true);

        assert!(backend.exit_prepared);
        assert!(!needs_drop_cleanup);
    }

    /// Shutting down a pump that isn't there is a no-op: the foreground still
    /// holds the framing afterwards, so an exit from a halted target can send
    /// its final continue.
    #[test]
    fn pump_shutdown_without_a_pump_keeps_the_framing() {
        let (_kernel, host) = UnixStream::pair().unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.link.set_inline_running(false);

        assert!(backend.shutdown_pump_with_stop().unwrap().is_none());
        assert!(matches!(backend.link, Link::Halted(_)));
        backend.reclaim_framing();
        assert!(matches!(backend.link, Link::Halted(_)));
        assert!(backend.framing().is_ok());

        // Keep unwinding safe: a framing-only fixture never enters Drop's
        // resume path.
        backend.link.set_inline_running(true);
    }

    #[test]
    fn exit_classifies_stray_single_step_but_spares_real_stops() {
        let pc = 0xfffff800_deadbeef;
        let mut managed = HashSet::new();
        let stop_at = |code: Option<u32>, pc: Option<u64>, is_bugcheck: bool| StopEvent {
            thread_id: None,
            exception_code: code,
            first_chance: code.map(|_| true),
            exception_address: pc,
            program_counter: pc,
            is_bugcheck,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            assisted_breakin: false,
        };

        // Stray single-step away from any installed int3: absorb it.
        assert!(exit_stop_is_stray_single_step(
            &stop_at(Some(STATUS_SINGLE_STEP), Some(pc), false),
            &managed,
        ));
        // Unknown PC still counts as stray (can't prove it's at a breakpoint).
        assert!(exit_stop_is_stray_single_step(
            &stop_at(Some(STATUS_SINGLE_STEP), None, false),
            &managed,
        ));

        // A single-step landing on one of our breakpoints is a real hit, not stray.
        managed.insert(pc);
        assert!(!exit_stop_is_stray_single_step(
            &stop_at(Some(STATUS_SINGLE_STEP), Some(pc), false),
            &managed,
        ));

        // A breakpoint stop or a bugcheck is never a stray single-step.
        assert!(!exit_stop_is_stray_single_step(
            &stop_at(Some(STATUS_BREAKPOINT), Some(0x1000), false),
            &managed,
        ));
        assert!(!exit_stop_is_stray_single_step(
            &stop_at(Some(STATUS_SINGLE_STEP), Some(0x1000), true),
            &managed,
        ));
    }

    #[test]
    fn has_pending_stop_flags_undrained_pump_stop_until_consumed() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let breakin_clone = host.try_clone().unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let reported_stop = Arc::new(AtomicBool::new(false));
        let join = {
            let shutdown = Arc::clone(&shutdown);
            let reported_stop = Arc::clone(&reported_stop);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop,
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };
        let pump = PumpHandle {
            join,
            stop_rx: rx,
            shutdown,
            reported_stop,
            breakin_requested: Arc::new(AtomicBool::new(false)),
        };
        let mut backend = kd_backend_with_pump(pump, breakin_clone);

        // Running, with the pump servicing the socket: nothing caught yet.
        assert!(backend.is_running());
        assert!(!backend.has_pending_stop());

        // Kernel emits a state-change; the pump catches it, flags reported_stop,
        // and exits with the stop sitting undrained in its channel.
        let pc = 0xfffff800_deadbeef;
        let mut payload = exception_state_change_payload(pc);
        payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                WIRE_FIRST_PACKET_ID,
                &payload,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !backend.has_pending_stop() {
            assert!(
                Instant::now() < deadline,
                "pump never flagged the reported stop"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        // The undrained-stop window: is_running() is still its stale post-continue
        // true, but has_pending_stop() reports the truth: the VM is halted.
        assert!(backend.is_running());
        assert!(backend.has_pending_stop());

        // Draining the stop reclaims the framing and clears the condition;
        // the caller's `record_stop` is what halts the link.
        let stop = backend
            .take_pump_stop(Some(Duration::from_secs(5)))
            .unwrap()
            .expect("pump reported no stop");
        assert_eq!(stop.program_counter, pc);
        assert!(matches!(backend.link, Link::RunningInline(_)));
        assert!(!backend.has_pending_stop());
        backend.record_stop(&stop);
        assert!(matches!(backend.link, Link::Halted(_)));
        // A halted backend resumes the target on drop; this mock kernel would
        // never acknowledge that.
        backend.exit_prepared = true;
    }

    /// A stale break-in byte makes the kernel re-break at the instruction it
    /// was resumed from. The pump steps past the int3, resumes, and reports
    /// only the genuine stop that follows; the foreground never blocks.
    #[test]
    fn pump_absorbs_rebreak_after_continue_and_reports_real_stop() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let resumed_from = 0xfffff800_deadbeef;
        let real_stop = 0xfffff800_cafe0000;
        let drain = ContinueDrain::new(
            resumed_from,
            0,
            HashSet::new(),
            HashSet::new(),
            context::build_register_map(),
        );
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    Some(drain),
                )
            })
        };

        let mut kernel_id = WIRE_FIRST_PACKET_ID;
        let mut send = |kernel: &mut UnixStream, packet_type: u16, payload: &[u8]| {
            kernel
                .write_all(&wire_data_packet(packet_type, kernel_id, payload))
                .unwrap();
            kernel.flush().unwrap();
            kernel_id ^= 1;
        };

        send(
            &mut kernel,
            PACKET_TYPE_KD_STATE_CHANGE64,
            &exception_state_change_payload(resumed_from),
        );

        // Service the pump's requests until it resumes the target: the
        // context round trip that steps past the int3, the DR7 read, and
        // ContinueApi2 itself.
        let mut context_written = 0usize;
        loop {
            let packet = read_wire_packet(&mut kernel);
            if u32::from_le_bytes(packet[0..4].try_into().unwrap()) == WIRE_CONTROL_LEADER {
                continue;
            }
            let host_id = u32::from_le_bytes(packet[8..12].try_into().unwrap());
            let request = &packet[WIRE_HEADER_SIZE..packet.len() - 1];
            let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
                .unwrap();
            let reply = match api_number {
                api::DBGKD_GET_CONTEXT => {
                    let mut context = vec![0u8; context::CONTEXT_SIZE];
                    context[context::OFFSET_RIP..context::OFFSET_RIP + 8]
                        .copy_from_slice(&resumed_from.to_le_bytes());
                    let mut reply = manipulate_reply_payload(api_number, 0, &[]);
                    reply.extend_from_slice(&context);
                    reply
                }
                api::DBGKD_SET_CONTEXT_EX => {
                    let chunk = &request[api::MANIPULATE_HEADER_SIZE..];
                    context_written += chunk.len();
                    let mut union = [0u8; 12];
                    union[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
                    manipulate_reply_payload(api_number, 0, &union)
                }
                api::DBGKD_READ_CONTROL_SPACE => read_special_registers_reply_payload(0),
                api::DBGKD_CONTINUE_API2 => break,
                other => panic!("unexpected request {other:#x} while absorbing a re-break"),
            };
            send(&mut kernel, PACKET_TYPE_KD_STATE_MANIPULATE, &reply);
        }
        assert_eq!(
            context_written,
            context::CONTEXT_SIZE,
            "the pump must write back the whole advanced context"
        );
        assert!(
            rx.try_recv().is_err(),
            "an absorbed re-break must not be reported"
        );

        send(
            &mut kernel,
            PACKET_TYPE_KD_STATE_CHANGE64,
            &exception_state_change_payload(real_stop),
        );
        let stop = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump reported no stop")
            .expect("pump reported an error");
        assert_eq!(stop.program_counter, real_stop);

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn pump_sends_breakin_after_peer_reset_while_waiting_for_reconnect() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
            .unwrap();
        kernel.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_breakin = false;
        let mut buf = [0u8; 64];
        while Instant::now() < deadline && !saw_breakin {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(saw_breakin, "pump should assist reboot reconnects");

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
        assert!(
            rx.try_recv().is_err(),
            "reset alone should not report a stop"
        );
    }

    #[test]
    fn pump_tags_stop_after_assisted_reconnect_breakin() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
            .unwrap();
        kernel.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_breakin = false;
        let mut buf = [0u8; 64];
        while Instant::now() < deadline && !saw_breakin {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(saw_breakin, "pump should send reconnect break-in");

        let pc = 0xfffff800_deadbeef;
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                WIRE_FIRST_PACKET_ID,
                &exception_state_change_payload(pc),
            ))
            .unwrap();
        kernel.flush().unwrap();

        let stop = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump reported no stop")
            .expect("pump reported an error");
        assert_eq!(stop.program_counter, pc);
        assert!(stop.target_reloaded);
        assert!(stop.assisted_breakin);

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn pump_surfaces_reloaded_transparent_state_change() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
            .unwrap();
        let pc = 0xfffff800_feedface;
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                WIRE_FIRST_PACKET_ID,
                &state_change_payload(DBG_KD_LOAD_SYMBOLS_STATE_CHANGE, pc),
            ))
            .unwrap();
        kernel.flush().unwrap();

        let stop = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump reported no stop")
            .expect("pump reported an error");
        assert_eq!(stop.new_state, DBG_KD_LOAD_SYMBOLS_STATE_CHANGE);
        assert_eq!(stop.program_counter, pc);
        assert!(stop.target_reloaded);

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn pump_sends_breakin_when_started_in_reconnect_assist_mode() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    Some(Duration::ZERO),
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_breakin = false;
        let mut buf = [0u8; 64];
        while Instant::now() < deadline && !saw_breakin {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(
            saw_breakin,
            "post-bugcheck reconnect assist should not require a reset packet first"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
        assert!(
            rx.try_recv().is_err(),
            "assist alone should not report a stop"
        );
    }

    #[test]
    fn pump_does_not_send_delayed_reconnect_assist_before_delay() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, _rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    Some(Duration::from_secs(60)),
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        let deadline = Instant::now() + Duration::from_millis(200);
        let mut saw_breakin = false;
        let mut buf = [0u8; 64];
        while Instant::now() < deadline {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if buf[..n].contains(&BREAKIN_BYTE) {
                        saw_breakin = true;
                        break;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(
            !saw_breakin,
            "delayed post-bugcheck reconnect assist should not fire immediately"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn await_refresh_sets_flag_without_breakin() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let handle = std::thread::spawn(move || {
            let mut framing = KdFraming::new(host.into());
            let mut saw_refresh = false;
            let stop = await_state_change(
                &mut framing,
                AwaitStateOptions {
                    arch: Arch::Amd64,
                    saw_kd_refresh: Some(&mut saw_refresh),
                    surface_all: false,
                    bugcheck: None,
                    bugcheck_capture: None,
                    deadline: None,
                    debug_log: None,
                },
            )
            .expect("await_state_change failed");
            (saw_refresh, stop)
        });

        let refresh = debug_io_print_payload(KD_REFRESH_MESSAGE);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_DEBUG_IO,
                WIRE_FIRST_PACKET_ID,
                &refresh,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let mut outbound = Vec::new();
        let mut buf = [0u8; 64];
        while outbound.len() < WIRE_HEADER_SIZE {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => outbound.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) => panic!("failed to read ACK: {e}"),
            }
        }
        assert!(
            outbound.len() >= WIRE_HEADER_SIZE,
            "refresh packet should be ACKed"
        );
        assert!(
            !outbound.contains(&BREAKIN_BYTE),
            "refresh ACK should not include a break-in"
        );

        let immediate_window = Instant::now() + Duration::from_millis(30);
        while Instant::now() < immediate_window {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    assert!(
                        !buf[..n].contains(&BREAKIN_BYTE),
                        "plain KD refresh should not trigger an immediate break-in"
                    );
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) => panic!("failed to read post-refresh output: {e}"),
            }
        }

        let pc = 0xfffff800_deadbeef;
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                WIRE_FIRST_PACKET_ID ^ 1,
                &exception_state_change_payload(pc),
            ))
            .unwrap();
        kernel.flush().unwrap();

        let (saw_refresh, stop) = handle.join().expect("await thread panicked");
        assert!(saw_refresh);
        assert_eq!(stop.program_counter, pc);
    }

    #[test]
    fn pump_does_not_breakin_immediately_on_bugcheck_refresh_print() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, _rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        let refresh = debug_io_print_payload(KD_REFRESH_MESSAGE);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_DEBUG_IO,
                WIRE_FIRST_PACKET_ID,
                &refresh,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 64];
        let mut outbound = Vec::new();
        while Instant::now() < deadline && outbound.len() < WIRE_HEADER_SIZE {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => outbound.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(
            outbound.len() >= WIRE_HEADER_SIZE,
            "pump should ACK the refresh print"
        );

        let mut saw_breakin = false;
        let immediate_window = Instant::now() + Duration::from_millis(30);
        while Instant::now() < immediate_window {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    outbound.extend_from_slice(&buf[..n]);
                    if buf[..n].contains(&BREAKIN_BYTE) {
                        saw_breakin = true;
                        break;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(
            !saw_breakin,
            "bugcheck refresh should not interrupt the remaining debug text immediately"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn pump_does_not_assist_non_e2_bugcheck_after_code_is_captured() {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, _rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        let refresh = debug_io_print_payload(KD_REFRESH_MESSAGE);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_DEBUG_IO,
                WIRE_FIRST_PACKET_ID,
                &refresh,
            ))
            .unwrap();
        let fatal = debug_io_print_payload(
            b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0x1,0x2,0x0,0x4)\r\n",
        );
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_DEBUG_IO,
                WIRE_FIRST_PACKET_ID ^ 1,
                &fatal,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let deadline = Instant::now() + Duration::from_millis(300);
        let mut saw_breakin = false;
        let mut buf = [0u8; 128];
        while Instant::now() < deadline {
            match kernel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if buf[..n].contains(&BREAKIN_BYTE) {
                        saw_breakin = true;
                        break;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => panic!("failed to read pump output: {e}"),
            }
        }
        assert!(
            !saw_breakin,
            "ordinary bugchecks should rely on the kernel-driven break once the code is known"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
    }

    #[test]
    fn only_exception_state_changes_surface_as_breaks() {
        // Exception breaks and unknown kinds are surfaced to the user
        assert!(!is_transparent_state_change(DBG_KD_EXCEPTION_STATE_CHANGE));
        assert!(!is_transparent_state_change(0xdead_beef));
        // Symbol load/unload and command-string notifications are continued
        assert!(is_transparent_state_change(
            DBG_KD_LOAD_SYMBOLS_STATE_CHANGE
        ));
        assert!(is_transparent_state_change(
            DBG_KD_COMMAND_STRING_STATE_CHANGE
        ));
    }

    #[test]
    fn pump_exits_on_shutdown_when_idle() {
        // Hold the kernel end open so the host socket stays connected
        let (_kernel, host) = UnixStream::pair().unwrap();
        let framing = KdFraming::new(host.into());
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_pump(
                    framing,
                    Arch::Amd64,
                    PumpLink {
                        stop_tx: tx,
                        shutdown,
                        reported_stop: Arc::new(AtomicBool::new(false)),
                    },
                    None,
                    DebugLog::new(DEBUG_LOG_CAPACITY),
                    None,
                )
            })
        };

        // No traffic: the pump should be parked on its read-timeout loop
        shutdown.store(true, Ordering::SeqCst);
        let _framing = handle.join().expect("pump thread panicked");
        assert!(rx.try_recv().is_err(), "idle pump should report no stop");
    }
}
