use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::bytes;
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, ContinueDisposition, DebugBackend, DebugCapability, DebugLog,
    DebugOutputPage, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, StopEvent, TrapState,
};
use crate::debugger_data::DebuggerDataCandidate;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::kd::framing::KdFraming;
use crate::memory::TranslationCache;
use crate::types::{Arch, Dtb, KernelLocation, VirtAddr};

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
mod breakpoints;
mod connect;
pub mod context;
pub mod context_arm64;
mod exit;
pub mod framing;
mod halt;
mod handles;
mod hw_breakpoints;
pub mod hwbp;
mod kdnet;
mod memory;
mod pump;
mod registers;
mod run;
mod transport;
use breakpoints::PendingWriteBreakpoint;
use halt::HaltRegisters;
use memory::LineCache;
use transport::KdTransport;

mod debug_io;
pub use debug_io::*;
mod file_io;
pub use file_io::*;
mod event_loop;
pub use event_loop::*;

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
    /// `DBGKD_ANY_CONTROL_REPORT`, verbatim. Every stop carries it, so the
    /// fields it holds cost nothing: see [`ControlReport`].
    control_report: Option<ControlReport>,
}

/// The control report a 64-bit KD state change carries after its exception
/// union, at [`CONTROL_REPORT_OFFSET`].
///
/// The bytes are kept verbatim because their meaning is per-architecture and
/// [`parse_state_change`] does not know the target's. Accessors interpret the
/// AMD64 layout; ARM64 callers ask for nothing yet.
///
/// Reading these instead of fetching registers is what keeps an absorbed
/// wrong-process breakpoint hit off the wire: a `CONTEXT` fetch is a 1.7 KB
/// reply, while this arrived with the stop.
#[derive(Debug, Clone)]
struct ControlReport(Vec<u8>);

/// `DBGKD_ANY_WAIT_STATE_CHANGE` header (32) plus its exception union
/// (`EXCEPTION_RECORD64` 0x98 + `FirstChance` ULONG, padded to 0xa0).
const CONTROL_REPORT_OFFSET: usize = 192;
/// `AMD64_DBGKD_CONTROL_REPORT`: Dr6, Dr7, EFlags, InstructionCount,
/// ReportFlags, InstructionStream[16], SegCs, SegDs, SegEs, SegFs.
const AMD64_CONTROL_REPORT_SIZE: usize = 48;
const AMD64_CONTROL_DR6_OFFSET: usize = 0;
const AMD64_CONTROL_DR7_OFFSET: usize = 8;
const AMD64_CONTROL_EFLAGS_OFFSET: usize = 16;

impl ControlReport {
    fn amd64(&self) -> Option<&[u8]> {
        self.0.get(..AMD64_CONTROL_REPORT_SIZE)
    }

    /// AMD64 DR6 and RFLAGS as the target reported them at the stop.
    fn amd64_trap_state(&self) -> Option<TrapState> {
        let report = self.amd64()?;
        Some(TrapState {
            eflags: u64::from(bytes::read_u32(report, AMD64_CONTROL_EFLAGS_OFFSET)),
            dr6: bytes::read_u64(report, AMD64_CONTROL_DR6_OFFSET),
        })
    }

    /// AMD64 DR7, which a continue must preserve.
    fn amd64_dr7(&self) -> Option<u64> {
        Some(bytes::read_u64(self.amd64()?, AMD64_CONTROL_DR7_OFFSET))
    }
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
const KD_RECONNECT_BREAKIN_INTERVAL: Duration = Duration::from_millis(250);
const KD_RECONNECT_BREAKIN_TRACE_EVERY: u32 = 8;
/// How long the background pump blocks on a socket read before looping back to
/// check its shutdown flag. Incoming packets are still serviced immediately
/// (this only bounds shutdown latency); the kernel writes each packet as one
/// burst, so a timeout this size only ever fires in the idle gap between packets.
const PUMP_POLL: Duration = Duration::from_millis(100);

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

    /// Move to halted while the foreground keeps the framing; a pumped or
    /// lost link is left alone.
    fn halt(&mut self) {
        self.hold_framing(false);
    }

    /// Move to running while the foreground keeps the framing.
    ///
    /// Taking the halt's registers is the point of the signature: nothing
    /// read while the target was halted describes it once it runs. Asking
    /// for them here is what spares every caller from remembering, and a new
    /// way to resume cannot be written without being handed them.
    fn resume(&mut self, registers: &mut HaltRegisters) {
        registers.running();
        self.hold_framing(true);
    }

    /// Hand the framing to a background pump, which runs the target.
    fn run_pumped(&mut self, pump: PumpHandle, registers: &mut HaltRegisters) {
        registers.running();
        *self = Self::RunningPumped(pump);
    }

    fn hold_framing(&mut self, running: bool) {
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
    /// A break-in we sent was answered by another stop (a module-load
    /// notification or a breakpoint hit that raced it), so the target still
    /// holds it: the next unmanaged `STATUS_BREAKPOINT` is that break-in,
    /// arriving late.
    late_breakin: bool,
    pending_write_breakpoint: Option<PendingWriteBreakpoint>,
    /// Per-processor register state for the current halt: the fetched
    /// `CONTEXT` and `KSPECIAL_REGISTERS`, and what the stop reported without
    /// a fetch. See [`HaltRegisters`].
    registers: HaltRegisters,
    /// Whether the current stop was an `int3` at one of our own installed
    /// sites. Recorded at the stop because the host disables that site before
    /// resuming, which erases the evidence from `managed_bp_addresses`.
    stop_was_managed_breakpoint: bool,
    /// A break the host asked for and the pump must not absorb, consumed by
    /// the next resume. See [`DebugBackend::surface_next_break_at`].
    surface_break_at: Option<u64>,
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
    /// [`restore_unowned_breakpoint_handles`](breakpoints::restore_unowned_breakpoint_handles).
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

impl KdBackend {
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
}

impl DebugBackend for KdBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn registers_are_context(&self) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        self.backend_name
    }

    fn set_kernel_dtb(&mut self, dtb: u64) {
        self.kernel_dtb_override = dtb;
        kd_trace!("kd: kernel page-table root = {dtb:#x}");
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.read_register_context()
    }

    /// KD reports TF and DR6 in every AMD64 state change, so an absorbed
    /// breakpoint hit can decide it has no single-step residue to clear
    /// without fetching a `CONTEXT` it would read two fields from.
    fn stop_trap_state(&mut self) -> Option<TrapState> {
        if self.arch != Arch::Amd64 {
            return None;
        }
        self.registers
            .report(self.current_processor)?
            .amd64_trap_state()
    }

    fn surface_next_break_at(&mut self, address: Option<u64>) {
        self.surface_break_at = address;
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.write_register_context(data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.install_breakpoint(addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.uninstall_breakpoint(addr)
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
        self.set_hardware_slot(slot, addr, access, len)
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
        self.clear_hardware_slot(slot)
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
        self.write_msr_value(processor, msr, value)
    }

    fn supports_target_control(&self) -> bool {
        true
    }

    fn supports_target_file_io(&self) -> bool {
        true
    }

    fn reboot_target(&mut self) -> Result<()> {
        self.request_reboot()
    }

    fn cause_bugcheck(&mut self) -> Result<()> {
        self.request_bugcheck()
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

    fn target_kernel_location(&mut self) -> Result<Option<KernelLocation>> {
        let hints = self.target_hints()?;
        Ok(Some(KernelLocation {
            dtb: hints.kernel_dtb,
            base: hints.kernel_base,
            arch: hints.arch,
        }))
    }

    fn target_debugger_data_hint(&mut self) -> Result<Option<DebuggerDataCandidate>> {
        self.debugger_data_hint()
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.continue_execution_with_disposition(ContinueDisposition::Handled)
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        self.resume_with(disposition)
    }

    fn step(&mut self) -> Result<()> {
        self.single_step()
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        self.break_in()
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        self.await_stop()
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.poll_stop(timeout)
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

#[cfg(test)]
mod tests;
