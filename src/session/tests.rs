use super::hits::{
    hardware_breakpoint_hit, rewind_thread_off_breakpoint, stopped_processor_matches,
};
use super::inspection::DBG_STATUS_WORKER;
use super::lifecycle::prepare_backend_after_cleanup;
use super::stepping::{
    RELEASE_BUDGET, RunPast, site_successors, stack_floor, step_over_current_breakpoint,
};
use super::*;
use crate::arch::{Arch, HwBreakpointAccess, RegisterInfo, amd64::REGISTER_BUFFER_SIZE, arm64};
use crate::backend::dbg_backend::{
    ContinueDisposition, ModuleNotification, TrapState, clear_trap_flag,
};
use crate::backend::partition_backend::PartitionVp;
use crate::base::memory::PAGE_SIZE;
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::{
    BreakpointConfig, BreakpointInfo, HardwareBreakpoint, HypercallFilter, PartitionFilter,
    StepFrame, ThreadScope,
};
use crate::nt::dmp::structs::Header64;
use crate::nt::expr::Expr;
use crate::nt::guest::ModuleInfo;
use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo};
use crate::nt::target::{MemoryKind, SelectedFrame};
use crate::session::exception_policy::{ExceptionPolicyFinalAction, ExceptionPolicyMode};
use iced_x86::{Decoder, DecoderOptions};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

/// DR6.BS (bit 14): a status bit outside B0-B3 that the functions under
/// test must leave untouched.
const DR6_BS: u64 = 1 << 14;
/// RFLAGS.RF (bit 16), the resume flag an execute hit must set.
const RF: u64 = 1 << 16;
/// RFLAGS.TF (bit 8), the trap flag `clear_trap_flag` clears.
const TF: u64 = 1 << 8;
/// An eflags value with a few innocent bits (IF | reserved bit 1) that
/// must survive every rewrite.
const EFLAGS_BASE: u64 = 0x202;

/// Hardware slot writes in order: `(slot, Some(address))` sets, `None` clears.
type HardwareWrites = Arc<Mutex<Vec<(usize, Option<u64>)>>>;
/// Software site writes in order: `(address, true)` plants, `false` lifts.
type SiteWrites = Arc<Mutex<Vec<(u64, bool)>>>;

/// Minimal register-file backend: a KD-layout register buffer the map's
/// offsets index into, plus a write counter for no-op assertions. Every
/// non-register operation is out of scope for these tests.
pub struct MockBackend {
    register_map: RegisterMap,
    regs: Vec<u8>,
    writes: usize,
    fail_writes: bool,
    allow_breakpoints: bool,
    exit_requests: Vec<bool>,
    fail_exit: bool,
    running: bool,
    interrupts: Arc<AtomicUsize>,
    continues: Arc<AtomicUsize>,
    interrupt_events: VecDeque<StopEvent>,
    modules_changed: bool,
    target_manages_sites: bool,
    /// Queued events surface only through `interrupt()`, never by polling:
    /// a guest that runs freely until the debugger breaks in.
    halts_only_on_interrupt: bool,
    /// The backend caught a stop no host has drained yet (a breakpoint hit
    /// while the host was idle); cleared once an event is handed out.
    pending_stop: bool,
    /// Sites the target reports as dropped by its last stop.
    dropped_sites: Vec<u64>,
    /// `set_breakpoint` (true) / `remove_breakpoint` (false) calls in order.
    /// Shared so a test can read it back after the backend moves into a
    /// session.
    site_writes: SiteWrites,
    /// `set_hardware_breakpoint` / `clear_hardware_breakpoint` calls.
    hardware_writes: HardwareWrites,
    /// Physical capacity behind a larger logical slot range, as on a GDB stub.
    hardware_limit: Option<usize>,
    /// Debug registers are the host's, as a GDB stub programs them: they
    /// trap whatever a processor runs, a guest partition's code included.
    host_debug_registers: bool,
    /// Register fetches, so a test can prove a path avoided one.
    reads: usize,
    /// How long a register fetch takes: the debugger's own work between
    /// runs, which can be slow (the first identification of the Windows
    /// hypervisor in a session takes over half a second).
    register_read_delay: Duration,
    /// TF and DR6 as a transport would report them with the stop.
    reported_trap_state: Option<TrapState>,
    /// Single steps are unsafe (the Windows hypervisor); `step()` then fails
    /// the test, and `continue_current_thread` lands on `lands_at`.
    single_step_unsafe: bool,
    /// Where the lone vCPU stops when resumed alone; `None` never stops.
    lands_at: Option<u64>,
    /// Where it stops on its first resumes alone, before `lands_at`.
    landings: VecDeque<u64>,
    /// Where it stands after every vCPU is resumed; `None` leaves it.
    released_to: Option<u64>,
    /// A run of every vCPU ends with this backend thread reporting its own
    /// stop (a breakpoint it hit), rather than by a break-in.
    released_stop_by: Option<&'static str>,
    /// The data address a watchpoint trapped on, reported with the stop
    /// that ends each run of every vCPU at `released_to`.
    released_watch: Option<u64>,
    /// The last stop handed out, and the one kept for the next wait (see
    /// [`DebugBackend::keep_last_stop`]).
    last_event: Option<StopEvent>,
    kept: Option<StopEvent>,
    /// Accept selecting (and report) one vCPU, as a stub does.
    one_vcpu: bool,
    /// The `_ETHREAD` each processor runs, shared with the session's target
    /// (see [`MockBackend::scheduling`]).
    threads: Arc<Mutex<HashMap<u16, VirtAddr>>>,
    /// Where single steps end, before stepping one byte on.
    step_landings: VecDeque<Landing>,
    /// The vCPU, and its processor, that reports the trap of a step that
    /// lands on `step_landings`, which then runs the landing's thread; by
    /// default the stepped one, processor 0.
    step_reported_by: Option<(&'static str, u16)>,
    /// The vCPU that reported the last step, while it is not processor 0.
    step_reporter: Option<&'static str>,
    /// Where runs of every vCPU stop on a breakpoint, before `released_to`.
    schedule: VecDeque<Landing>,
    /// Where runs of the lone vCPU stop on a breakpoint, before `landings`.
    alone_schedule: VecDeque<Landing>,
    /// Another vCPU (and the site it stands on) that traps again at once
    /// whenever resumed: a run of every vCPU ends with its stop there, the
    /// step's vCPU not moved. A run that holds it moves the step's vCPU as
    /// a run of every vCPU otherwise does, once the parked vCPU has been
    /// resumed `freed_after_resumes` times (to take an IPI the step's
    /// vCPU waits on); before that, the step's vCPU stays.
    parked_vcpu: Option<(&'static str, u64)>,
    freed_after_resumes: usize,
    /// The times the parked vCPU was resumed.
    parked_resumes: Arc<AtomicUsize>,
    /// The vCPU selected, whose registers a fetch returns: the parked one's
    /// IP is its site, every other vCPU is processor 0.
    selected: String,
    /// A stop the next wait returns at once, before any other.
    immediate_stop: Option<StopEvent>,
    /// Each processor's MSRs and 32-bit device registers by physical
    /// address; a read of any other faults, as on hardware.
    msrs: HashMap<(u16, u32), u64>,
    device_registers: HashMap<(u16, u64), u32>,
    /// Step only the vCPU that reported the last stop, as ARM64 KD does.
    stopping_processor_only: bool,
    /// The first step is cut short by this vCPU (and processor) hitting a
    /// breakpoint where its landing stands; the stepped vCPU's step stays
    /// armed, and lands on the second landing when the target resumes.
    step_cut_short_by: Option<(&'static str, u16, Landing, Landing)>,
    armed_step: Option<Landing>,
    /// The vCPU that reported the last stop.
    stopped_by: &'static str,
    /// The steps the backend was asked for.
    steps: Arc<AtomicUsize>,
}

/// Where processor 0 stands after a mock step or run: its IP and stack
/// pointer, and the thread it runs.
#[derive(Clone, Copy)]
struct Landing {
    rip: u64,
    rsp: u64,
    ethread: u64,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            register_map: Arch::Amd64.register_map().clone(),
            regs: vec![0u8; REGISTER_BUFFER_SIZE],
            writes: 0,
            fail_writes: false,
            allow_breakpoints: false,
            exit_requests: Vec::new(),
            fail_exit: false,
            running: false,
            interrupts: Arc::new(AtomicUsize::new(0)),
            continues: Arc::new(AtomicUsize::new(0)),
            interrupt_events: VecDeque::new(),
            modules_changed: false,
            target_manages_sites: false,
            halts_only_on_interrupt: false,
            pending_stop: false,
            dropped_sites: Vec::new(),
            site_writes: Arc::new(Mutex::new(Vec::new())),
            hardware_writes: Arc::new(Mutex::new(Vec::new())),
            hardware_limit: None,
            host_debug_registers: false,
            reads: 0,
            register_read_delay: Duration::ZERO,
            reported_trap_state: None,
            single_step_unsafe: false,
            lands_at: None,
            landings: VecDeque::new(),
            released_to: None,
            released_stop_by: None,
            released_watch: None,
            last_event: None,
            kept: None,
            one_vcpu: false,
            threads: Arc::new(Mutex::new(HashMap::new())),
            step_landings: VecDeque::new(),
            step_reported_by: None,
            step_reporter: None,
            schedule: VecDeque::new(),
            alone_schedule: VecDeque::new(),
            parked_vcpu: None,
            freed_after_resumes: 0,
            parked_resumes: Arc::new(AtomicUsize::new(0)),
            selected: String::new(),
            immediate_stop: None,
            msrs: HashMap::new(),
            device_registers: HashMap::new(),
            stopping_processor_only: false,
            step_cut_short_by: None,
            armed_step: None,
            stopped_by: "p01.01",
            steps: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl MockBackend {
    pub fn running(mut self) -> Self {
        self.running = true;
        self
    }

    /// Model a backend that selects vCPU `p01.01` (and accepts any id).
    pub fn one_vcpu(mut self) -> Self {
        self.one_vcpu = true;
        self
    }

    /// Model a transport that reports TF and DR6 with the stop, as KD's
    /// state-change control report does.
    fn reporting_trap_state(mut self, eflags: u64, dr6: u64) -> Self {
        self.reported_trap_state = Some(TrapState { eflags, dr6 });
        self
    }

    /// Model a target that owns its breakpoint table (KD), not a stub
    /// that leaves our patched byte in place across a stop.
    fn target_managed_sites(mut self) -> Self {
        self.target_manages_sites = true;
        self
    }

    /// Model a stub that owns the processor's debug registers and exposes
    /// none of them, as a GDB target description does.
    fn without_debug_registers(mut self) -> Self {
        let register = |name: &str, offset, size, regnum| RegisterInfo {
            name: name.to_string(),
            offset,
            size,
            regnum,
        };
        self.register_map = RegisterMap::from_registers(vec![
            register("rsp", 0, 8, 0),
            register("rip", 8, 8, 1),
            register("eflags", 16, 4, 2),
        ]);
        self.regs = vec![0u8; 20];
        self
    }

    pub fn queue_interrupt(&mut self, event: StopEvent) {
        self.interrupt_events.push_back(event);
    }

    pub fn halts_only_on_interrupt(mut self) -> Self {
        self.halts_only_on_interrupt = true;
        self
    }

    pub fn with_pending_stop(mut self) -> Self {
        self.pending_stop = true;
        self
    }

    /// Take software breakpoints, as KD does.
    pub fn with_breakpoints(mut self) -> Self {
        self.allow_breakpoints = true;
        self
    }

    /// Put processor 0 at `rip`, its stack at `rsp`, running `ethread`.
    pub fn standing_at(mut self, rip: u64, rsp: u64, ethread: u64) -> Self {
        self.land(Landing { rip, rsp, ethread });
        self
    }

    /// Runs of every vCPU stop on a breakpoint at each `(rip, rsp,
    /// ethread)` in turn, then run freely.
    pub fn runs_stopping_at(mut self, stops: &[(u64, u64, u64)]) -> Self {
        self.schedule
            .extend(
                stops
                    .iter()
                    .map(|&(rip, rsp, ethread)| Landing { rip, rsp, ethread }),
            );
        self
    }

    /// Make every register fetch take `delay`.
    pub fn with_register_read_delay(mut self, delay: Duration) -> Self {
        self.register_read_delay = delay;
        self
    }

    /// The `set_breakpoint` / `remove_breakpoint` log, readable after the
    /// backend moves into a session.
    pub fn site_log(&self) -> Arc<Mutex<Vec<(u64, bool)>>> {
        Arc::clone(&self.site_writes)
    }

    /// The count of runs of every vCPU, readable after the backend moves
    /// into a session.
    pub fn continue_count(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.continues)
    }

    /// Give `processor` MSR `msr`, read as `value`.
    pub fn with_msr(mut self, processor: u16, msr: u32, value: u64) -> Self {
        self.msrs.insert((processor, msr), value);
        self
    }

    /// Give `processor` a 32-bit device register at physical `address`.
    pub fn with_device_register(mut self, processor: u16, address: u64, value: u32) -> Self {
        self.device_registers.insert((processor, address), value);
        self
    }

    pub fn set(&mut self, name: &str, value: u64) {
        self.register_map
            .write_u64(name, &mut self.regs, value)
            .unwrap();
    }

    fn get(&self, name: &str) -> u64 {
        self.register_map.read_u64(name, &self.regs).unwrap()
    }

    /// The architecture of the mock's register file: AMD64's by default,
    /// ARM64's when a test gives it that map.
    fn arch(&self) -> Arch {
        if self.register_map.contains("rip") {
            Arch::Amd64
        } else {
            Arch::Arm64
        }
    }

    fn set_pc(&mut self, value: u64) {
        self.set(self.arch().pc_register(), value);
    }

    fn pc(&self) -> u64 {
        self.get(self.arch().pc_register())
    }

    /// Put processor 0 at `landing`.
    fn land(&mut self, landing: Landing) {
        self.set_pc(landing.rip);
        self.set(self.arch().sp_register(), landing.rsp);
        self.threads.lock().insert(0, VirtAddr(landing.ethread));
    }
}

impl DebugBackend for MockBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.reads += 1;
        std::thread::sleep(self.register_read_delay);
        let mut regs = self.regs.clone();
        if let Some((vcpu, site)) = self.parked_vcpu
            && self.selected == vcpu
        {
            self.register_map
                .write_u64(self.arch().pc_register(), &mut regs, site)?;
        }
        Ok(regs)
    }
    fn stop_trap_state(&mut self) -> Option<TrapState> {
        self.reported_trap_state
    }
    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.writes += 1;
        if self.fail_writes {
            return Err(Error::Kd("injected register write failure".into()));
        }
        self.regs = data.to_vec();
        Ok(())
    }
    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.allow_breakpoints {
            self.site_writes.lock().push((addr, true));
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.allow_breakpoints {
            self.site_writes.lock().push((addr, false));
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn target_manages_breakpoint_sites(&self) -> bool {
        self.target_manages_sites
    }
    /// The tests put code at low addresses, user space by address; a mock
    /// that takes breakpoints takes them there too, as KD does.
    fn supports_user_mode_breakpoints(&self) -> bool {
        self.allow_breakpoints
    }
    fn hardware_breakpoint_slots(&self) -> usize {
        self.hardware_limit
            .map_or(Arch::Amd64.debug_registers().slots(), |limit| limit + 4)
    }
    fn set_hardware_breakpoint(
        &mut self,
        slot: usize,
        addr: u64,
        _access: HwBreakpointAccess,
        _len: u8,
    ) -> Result<()> {
        if self.hardware_limit.is_some_and(|limit| slot >= limit) {
            return Err(Error::HardwareBreakpointRefused {
                address: addr,
                response: "E22".into(),
            });
        }
        self.hardware_writes.lock().push((slot, Some(addr)));
        Ok(())
    }
    fn clear_hardware_breakpoint(&mut self, slot: usize) -> Result<()> {
        self.hardware_writes.lock().push((slot, None));
        Ok(())
    }
    fn supports_watchpoints(&self) -> bool {
        self.host_debug_registers
    }
    fn hardware_breakpoints_trap_in_host(&self) -> bool {
        self.host_debug_registers
    }
    fn sites_dropped_by_stop(&self) -> Vec<u64> {
        self.dropped_sites.clone()
    }
    fn continue_execution(&mut self) -> Result<()> {
        if self.kept.is_some() {
            self.running = true;
            return Ok(());
        }
        self.continues.fetch_add(1, Ordering::Relaxed);
        self.running = true;
        if let Some(landing) = self.armed_step.take() {
            self.land(landing);
            self.stopped_by = "p01.01";
            self.interrupt_events.push_back(single_step_event());
            return Ok(());
        }
        if let Some((vcpu, site)) = self.parked_vcpu {
            self.parked_resumes.fetch_add(1, Ordering::Relaxed);
            let mut event = breakpoint_event(site);
            event.thread_id = Some(vcpu.into());
            self.immediate_stop = Some(event);
            return Ok(());
        }
        if let Some(landing) = self.schedule.pop_front() {
            self.land(landing);
            self.interrupt_events
                .push_back(breakpoint_event(landing.rip));
        } else if let Some(address) = self.released_to {
            self.set_pc(address);
            let mut event = breakpoint_event(address);
            event.watchpoint_address = self.released_watch;
            self.interrupt_events.push_back(event);
        }
        Ok(())
    }
    fn single_step_unsafe(&self) -> bool {
        self.single_step_unsafe
    }
    fn steps_only_the_stopping_processor(&self) -> bool {
        self.stopping_processor_only
    }
    fn halts_in_windows_hypervisor(&self) -> bool {
        self.single_step_unsafe
    }
    /// The lone vCPU reaches `alone_schedule`, then `landings`, then
    /// `lands_at`, and reports a breakpoint there.
    fn continue_current_thread(&mut self) -> Result<()> {
        if self.kept.is_some() {
            self.running = true;
            return Ok(());
        }
        self.running = true;
        if let Some(landing) = self.alone_schedule.pop_front() {
            self.land(landing);
            self.interrupt_events
                .push_back(breakpoint_event(landing.rip));
        } else if let Some(address) = self.landings.pop_front().or(self.lands_at) {
            self.set_pc(address);
            self.interrupt_events.push_back(breakpoint_event(address));
        }
        Ok(())
    }
    /// A run that holds the parked vCPU (see `parked_vcpu`), which must not
    /// be among `threads`; the break-in answers it.
    fn continue_threads(&mut self, threads: &[String]) -> Result<()> {
        let (parked, _) = self.parked_vcpu.ok_or(Error::NotSupported)?;
        assert!(
            !threads.iter().any(|thread| thread == parked),
            "a run that holds {parked} resumed it: {threads:?}"
        );
        self.running = true;
        if self.parked_resumes.load(Ordering::Relaxed) >= self.freed_after_resumes
            && let Some(address) = self.released_to
        {
            self.set_pc(address);
        }
        self.interrupt_events.push_back(breakpoint_event(self.pc()));
        Ok(())
    }
    /// A step lands on `step_landings`, then one shortest instruction on,
    /// reported by the queued single-step event.
    fn step(&mut self) -> Result<()> {
        assert!(
            !self.single_step_unsafe,
            "single-stepped where it is unsafe"
        );
        if self.stopping_processor_only && self.selected != self.stopped_by {
            return Err(Error::Kd(format!(
                "{} stopped the target; {} cannot step",
                self.stopped_by, self.selected
            )));
        }
        self.steps.fetch_add(1, Ordering::Relaxed);
        if let Some((vcpu, processor, hit, armed)) = self.step_cut_short_by.take() {
            self.set_pc(hit.rip);
            self.threads.lock().insert(processor, VirtAddr(hit.ethread));
            self.armed_step = Some(armed);
            self.stopped_by = vcpu;
            let mut event = breakpoint_event(hit.rip);
            event.thread_id = Some(vcpu.into());
            self.interrupt_events.push_back(event);
            return Ok(());
        }
        let mut event = single_step_event();
        self.step_reporter = None;
        if let Some(landing) = self.step_landings.pop_front() {
            self.land(landing);
            if let Some((vcpu, processor)) = self.step_reported_by {
                self.threads
                    .lock()
                    .insert(processor, VirtAddr(landing.ethread));
                event.thread_id = Some(vcpu.into());
                self.step_reporter = Some(vcpu);
            }
        } else {
            let next = self.pc() + self.arch().code_machine().min_instruction_bytes() as u64;
            self.set_pc(next);
        }
        self.interrupt_events.push_back(event);
        Ok(())
    }
    fn interrupt(&mut self) -> Result<StopEvent> {
        if let Some(event) = self.kept.take() {
            self.running = false;
            return Ok(event);
        }
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        let event = self
            .interrupt_events
            .pop_front()
            .ok_or(Error::NotSupported)?;
        self.running = false;
        self.last_event = Some(event.clone());
        Ok(event)
    }
    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        if let Some(event) = self.kept.take() {
            self.running = false;
            return Ok(event);
        }
        let event = self
            .interrupt_events
            .pop_front()
            .ok_or(Error::NotSupported)?;
        self.running = false;
        self.last_event = Some(event.clone());
        Ok(event)
    }
    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        if let Some(event) = self.kept.take() {
            self.running = false;
            return Ok(Some(event));
        }
        if let Some(event) = self.immediate_stop.take() {
            self.running = false;
            self.last_event = Some(event.clone());
            return Ok(Some(event));
        }
        if let Some(thread) = self.released_stop_by
            && self.running
            && self.continues.load(Ordering::Relaxed) > 0
        {
            let mut event = self
                .interrupt_events
                .pop_front()
                .ok_or(Error::NotSupported)?;
            event.thread_id = Some(thread.into());
            self.running = false;
            self.last_event = Some(event.clone());
            return Ok(Some(event));
        }
        if self.halts_only_on_interrupt {
            return Ok(None);
        }
        let event = self.interrupt_events.pop_front();
        if let Some(event) = &event {
            self.running = false;
            self.pending_stop = false;
            self.last_event = Some(event.clone());
        }
        Ok(event)
    }
    fn keep_last_stop(&mut self) -> Result<()> {
        self.kept = Some(self.last_event.clone().ok_or(Error::NotSupported)?);
        Ok(())
    }
    fn stop_kept(&self) -> bool {
        self.kept.is_some()
    }
    fn thread_list(&mut self) -> Result<Vec<String>> {
        let (parked, _) = self.parked_vcpu.ok_or(Error::NotSupported)?;
        Ok(vec!["p01.01".to_string(), parked.to_string()])
    }
    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        if self.one_vcpu {
            thread_id.clone_into(&mut self.selected);
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn stopped_thread_id(&mut self) -> Result<String> {
        if self.one_vcpu {
            Ok(self.step_reporter.unwrap_or("p01.01").to_string())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn is_running(&self) -> bool {
        self.running
    }
    fn has_pending_stop(&self) -> bool {
        self.pending_stop
    }
    fn supports_msr(&self) -> bool {
        !self.msrs.is_empty()
    }
    fn read_msr(&mut self, processor: u16, msr: u32) -> Result<u64> {
        self.msrs
            .get(&(processor, msr))
            .copied()
            .ok_or_else(|| Error::Kd(format!("#GP reading MSR {msr:#x} on {processor}")))
    }
    fn read_device_memory(&mut self, processor: u16, address: u64, buf: &mut [u8]) -> Result<()> {
        let value = self
            .device_registers
            .get(&(processor, address))
            .filter(|_| buf.len() == 4)
            .ok_or_else(|| Error::Kd(format!("no register at {address:#x} on {processor}")))?;
        buf.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn take_modules_changed(&mut self) -> bool {
        take(&mut self.modules_changed)
    }
    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        self.exit_requests.push(leave_running);
        if self.fail_exit {
            Err(Error::Kd("injected backend teardown failure".into()))
        } else {
            Ok(())
        }
    }
}

fn single_step_event() -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: Some(STATUS_SINGLE_STEP),
        first_chance: Some(true),
        exception_address: None,
        program_counter: None,
        watchpoint_address: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        module_event: None,
        assisted_breakin: false,
        break_in: false,
    }
}

pub fn breakpoint_event(pc: u64) -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: Some(STATUS_BREAKPOINT),
        first_chance: Some(true),
        exception_address: Some(pc),
        program_counter: Some(pc),
        watchpoint_address: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        module_event: None,
        assisted_breakin: false,
        break_in: false,
    }
}

fn module_change_event() -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        watchpoint_address: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: true,
        module_event: None,
        assisted_breakin: false,
        break_in: false,
    }
}

pub fn session_with_mock(backend: MockBackend) -> Session {
    let mut session = session_over_memory(0x1000, &[0; 0x100]);
    session.backend = Box::new(backend);
    session.register_map = Arch::Amd64.register_map().clone();
    session
}

/// A session over `code` at 0x1000 whose one vCPU (`p01.01`, a
/// [`MockBackend::one_vcpu`]) runs the threads the backend lands it on.
pub fn session_running_code(code: &[u8], backend: MockBackend) -> Session {
    let threads = Arc::clone(&backend.threads);
    let mut session = stepping_session(code, backend);
    session.target.test_current_threads = Some(threads);
    session.current_thread = "p01.01".into();
    session
}

#[test]
fn bugcheck_exception_record_uses_bugcheck_code() {
    let mut session = session_over_memory(0x1000, &[0; 0x100]);
    let mut stop = breakpoint_event(0x1000);
    stop.exception_code = None;
    stop.bugcheck = Some(BugcheckInfo {
        code: 0xdead_beef,
        parameters: [0x1020, 2, 3, 4],
        driver: None,
    });
    session.last_event = Some(LastEvent::new(stop));

    assert_eq!(
        session.current_exception_record().unwrap().code,
        0xdead_beef
    );
}

/// A context that holds only some registers (a trap frame, the VTL0 state the
/// Windows hypervisor saves) walks with the rest unknown: frame 0 reports what
/// the context holds and never a zero for a register it lacks, and the stack
/// is not the vCPU's writable register file.
#[test]
fn a_sparse_context_walks_with_its_missing_registers_unknown() {
    let mut session = session_over_memory(0x1000, &[0; 0x100]);
    session.register_map = Arch::Amd64.register_map().clone();
    let supplied = HashMap::from([
        ("rip".to_string(), 0x1010),
        ("rsp".to_string(), 0x1080),
        ("cs".to_string(), 0x10),
    ]);
    session.select_frame(SelectedFrame::from_registers(
        session.target.arch(),
        0,
        supplied,
    ));

    let (trace, _, live) = session.recovered_backtrace(4).unwrap();

    assert!(!live);
    let frame = &trace.frames[0].registers;
    assert_eq!(frame.get("rip"), Some(&0x1010));
    assert_eq!(frame.get("rsp"), Some(&0x1080));
    assert_eq!(frame.get("cs"), Some(&0x10));
    for missing in ["rax", "rbx", "rbp", "rsi", "rdi", "r12", "r15", "eflags"] {
        assert!(
            !frame.contains_key(missing),
            "{missing} = {:?}",
            frame.get(missing)
        );
    }
}

/// The status snapshot MCP, the SDK, and DAP take after every call reports
/// where the target is; it must not move what the user selected to inspect,
/// or `.frame`, `.cxr`, and `.thread` would not last until the next call.
#[test]
fn a_status_snapshot_keeps_the_selected_thread_and_frame() {
    let mut session = session_with_mock(MockBackend {
        one_vcpu: true,
        ..MockBackend::default()
    });
    session.current_thread = "p1.1".to_string();
    let thread = crate::nt::target::sample_thread();
    session.target.set_parked_windows_thread(thread.clone());
    session.parked_windows_thread = Some(thread.ethread);
    session.select_frame(SelectedFrame::from_registers(
        session.target.arch(),
        2,
        HashMap::from([("rip".to_string(), 0x1010), ("rsp".to_string(), 0x1080)]),
    ));

    let status = session.run_status();

    assert!(!status.running);
    assert_eq!(
        session.parked_windows_thread().map(|thread| thread.ethread),
        Some(thread.ethread)
    );
    assert_eq!(
        session
            .target
            .selected_frame
            .as_ref()
            .map(|frame| frame.index),
        Some(2)
    );
}

fn session_over_arm64_memory(base: u64, memory: &[u8]) -> Session {
    let block = TriageBlock {
        address: base,
        offset: 0,
        size: memory.len() as u32,
    };
    let mut dump = make_triage_dump(&[block], &[(base, memory)]);
    let machine_offset = std::mem::offset_of!(Header64, machine_image_type);
    dump[machine_offset..machine_offset + 4]
        .copy_from_slice(&u32::from(Arch::Arm64.machine_type()).to_le_bytes());

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = temp_dir().join(format!("ntoseye-session-arm64-{sequence}-{}.dmp", id()));
    write(&path, dump).unwrap();
    let session = Session::open(&TargetSpec::Dump(path.clone())).unwrap();
    remove_file(path).unwrap();
    session
}

#[test]
fn page_in_result_reads_arm64_pc_and_first_argument() {
    let mut session = session_over_arm64_memory(0x1000, &[0; 0x100]);
    assert_eq!(session.target.arch(), Arch::Arm64);

    let mut backend = MockBackend {
        register_map: Arch::Arm64.register_map().clone(),
        regs: vec![0; arm64::REGISTER_BUFFER_SIZE],
        ..MockBackend::default()
    };
    backend.set("pc", 0x2000);
    backend.set("x0", DBG_STATUS_WORKER);
    session.register_map = backend.register_map.clone();
    session.backend = Box::new(backend);

    let report = session.page_in_result(VirtAddr(0x1000), VirtAddr(0x2000));

    assert!(report.from_worker);
}

/// Stopped on `KeBugCheckEx`'s first instruction, the code and first three
/// parameters are in registers and the fourth, its fifth argument, on the
/// stack past the return address and the four registers' shadow space.
#[test]
fn a_bugcheck_trap_reads_its_last_parameter_past_the_shadow_space() {
    let mut memory = [0u8; 0x100];
    for (slot, value) in memory[0x80..0xb0]
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(0x10u64..)
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let mut session = session_over_memory(0x1000, &memory);
    let mut backend = MockBackend::default();
    backend.set("rcx", 0x139);
    backend.set("rdx", 3);
    backend.set("r8", 0xffff_8000_1000_0000);
    backend.set("r9", 0xffff_8000_2000_0000);
    backend.set("rsp", 0x1080);
    session.register_map = backend.register_map.clone();
    session.backend = Box::new(backend);

    let info = session.bugcheck_from_trap().unwrap();

    assert_eq!(info.code, 0x139);
    assert_eq!(
        info.parameters,
        [3, 0xffff_8000_1000_0000, 0xffff_8000_2000_0000, 0x15]
    );
}

/// With nothing attached, the bytes `db` and `s` show are the halted
/// context's, the same space an expression like `poi(addr)` reads.
#[test]
fn memory_reads_follow_the_halted_context_root() {
    const BASE: u64 = 0x10000;
    const USER_VA: u64 = 0x7ff6_1234_5000;
    let va = VirtAddr(USER_VA);
    let mut memory = vec![0u8; 5 * PAGE_SIZE];
    let mut link = |table: u64, index: usize, next: u64| {
        let at = (table - BASE) as usize + index * 8;
        memory[at..at + 8].copy_from_slice(&(next | 0b111).to_le_bytes());
    };
    link(BASE, va.pml4_index(), BASE + 0x1000);
    link(BASE + 0x1000, va.pdpt_index(), BASE + 0x2000);
    link(BASE + 0x2000, va.pd_index(), BASE + 0x3000);
    link(BASE + 0x3000, va.pt_index(), BASE + 0x4000);
    memory[0x4000..0x4004].copy_from_slice(b"USER");
    let mut session = session_over_memory(BASE, &memory);
    session.target.set_context_dtb_override(BASE);

    let mut bytes = [0u8; 4];
    session.target.read_masked(va, &mut bytes).unwrap();
    let hits = session.search(va, b"SE", 4).unwrap().matches;

    assert_eq!(&bytes, b"USER");
    assert_eq!(hits, [USER_VA + 1]);
}

/// A WOW64 process's x86 code builds 32-bit string descriptors: `Buffer` is a
/// 4-byte pointer at offset 4. `.effmach x86` (or an explicit width) reads
/// them with WOW64 ntdll's layout instead of the kernel's 64-bit one.
#[test]
fn string_descriptors_follow_the_requested_width() {
    use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo};

    let mut memory = [0u8; 0x40];
    memory[0..2].copy_from_slice(&4u16.to_le_bytes());
    memory[4..8].copy_from_slice(&0x1020u32.to_le_bytes());
    memory[8..12].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    memory[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
    memory[0x14..0x18].copy_from_slice(&0x1030u32.to_le_bytes());
    memory[0x20..0x24].copy_from_slice(&[b'o', 0, b'k', 0]);
    memory[0x30..0x32].copy_from_slice(b"hi");
    let mut session = session_over_memory(0x1000, &memory);
    let dtb = session.target.current_dtb();
    let descriptor = |name: &str, pointer_size: u8| TypeInfo {
        name: name.to_string(),
        pointer_size,
        size: 2 * usize::from(pointer_size),
        fields: [
            ("Length", 0, 2, ParsedType::Primitive("USHORT".into())),
            (
                "MaximumLength",
                2,
                2,
                ParsedType::Primitive("USHORT".into()),
            ),
            (
                "Buffer",
                u32::from(pointer_size),
                u64::from(pointer_size),
                ParsedType::Pointer(Box::new(ParsedType::Primitive("CHAR".into()))),
            ),
        ]
        .into_iter()
        .map(|(field, offset, size, type_data)| {
            (
                field.to_string(),
                FieldInfo {
                    offset,
                    size,
                    type_data,
                },
            )
        })
        .collect(),
    };
    let symbols = &session.target.symbols;
    symbols.set_kernel(Some(1), dtb);
    symbols.inject_module_for_test(
        1,
        vec![descriptor("_UNICODE_STRING", 8), descriptor("_STRING", 8)],
        &[],
    );
    symbols.inject_module_for_test(
        2,
        vec![descriptor("_UNICODE_STRING", 4), descriptor("_STRING", 4)],
        &[],
    );
    symbols.register_module_for_test(2, "ntdll32", dtb);
    let unicode = VirtAddr(0x1000);

    let native = session.target.read_unicode_string(unicode, 64);
    session.target.effmach = Some(crate::base::types::CodeMachine::X86);
    let bits = session.target.data_bitness();

    assert!(
        native.is_err(),
        "the 64-bit layout reads 0xdeadbeef as Buffer"
    );
    assert_eq!(
        session.target.read_unicode_string(unicode, bits).unwrap(),
        "ok"
    );
    assert_eq!(
        session
            .target
            .read_ansi_string(VirtAddr(0x1010), bits)
            .unwrap(),
        "hi"
    );
}

#[test]
fn terminated_reads_join_utf16_page_chunks_and_keep_readable_prefixes() {
    let base = 0x1000;
    let mut mapped = vec![0xff; PAGE_SIZE + 4];
    mapped[PAGE_SIZE - 1..PAGE_SIZE + 3].copy_from_slice(&[0x41, 0x00, 0x00, 0x00]);
    let session = session_over_memory(base, &mapped);

    let read = session
        .read_terminated(VirtAddr(base + PAGE_SIZE as u64 - 1), 2, 2)
        .unwrap();
    assert_eq!(read.bytes, vec![0x41, 0x00]);
    assert!(!read.unreadable);

    let page = vec![b'X'; PAGE_SIZE];
    let session = session_over_memory(base, &page);
    let read = session
        .read_terminated(VirtAddr(base + PAGE_SIZE as u64 - 2), 4, 1)
        .unwrap();
    assert_eq!(read.bytes, vec![b'X', b'X']);
    assert!(read.unreadable);

    // The unit budget ends the read before a terminator is found.
    let read = session.read_terminated(VirtAddr(base), 3, 1).unwrap();
    assert_eq!(read.bytes, b"XXX");
    assert!(!read.unreadable);
}

#[test]
fn with_target_halted_runs_directly_when_already_halted() {
    let backend = MockBackend::default();
    let interrupts = Arc::clone(&backend.interrupts);
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    let value = session.with_target_halted(|_| Ok(7u32)).unwrap();

    assert_eq!(value, 7);
    assert_eq!(interrupts.load(Ordering::Relaxed), 0);
    assert_eq!(continues.load(Ordering::Relaxed), 0);
}

#[test]
fn with_target_halted_interrupts_edits_and_resumes_running_target() {
    let mut backend = MockBackend::default().running();
    let interrupts = Arc::clone(&backend.interrupts);
    let continues = Arc::clone(&backend.continues);
    backend.queue_interrupt(breakpoint_event(0x2000));
    let mut session = session_with_mock(backend);

    session.with_target_halted(|_| Ok(())).unwrap();

    assert_eq!(interrupts.load(Ordering::Relaxed), 1);
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(session.backend.is_running());
}

#[test]
fn with_target_halted_resumes_after_edit_error() {
    let mut backend = MockBackend::default().running();
    let continues = Arc::clone(&backend.continues);
    backend.queue_interrupt(breakpoint_event(0x2000));
    let mut session = session_with_mock(backend);

    let error = session
        .with_target_halted(|_| Err::<(), _>(Error::DebugInfo("edit failed".into())))
        .unwrap_err();

    assert!(error.to_string().contains("edit failed"));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(session.backend.is_running());
}

/// The gdb backend reports its `SIGINT` break-in with no exception code,
/// which is still the edit's own break-in and so is resumed, not parked.
#[test]
fn with_target_halted_resumes_a_gdb_shaped_break_in() {
    let mut backend = MockBackend::default().running();
    backend.set("rip", 0x2000);
    let continues = Arc::clone(&backend.continues);
    backend.queue_interrupt(StopEvent {
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        break_in: true,
        ..breakpoint_event(0x2000)
    });
    let mut session = session_with_mock(backend);

    session.with_target_halted(|_| Ok(())).unwrap();

    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(session.backend.is_running());
    assert!(session.parked_stop.is_none());
}

#[test]
fn with_target_halted_parks_a_genuine_pending_breakpoint() {
    let mut backend = MockBackend::default().running();
    backend.set("rip", 0x1000);
    let continues = Arc::clone(&backend.continues);
    backend.queue_interrupt(breakpoint_event(0x1000));
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);

    session.with_target_halted(|_| Ok(())).unwrap();

    assert_eq!(continues.load(Ordering::Relaxed), 0);
    assert!(!session.backend.is_running());
    assert!(matches!(
        session.wait_stop(&Cancel::poll(), true),
        Ok(ContinueOutcome::Breakpoint { id: 1, .. })
    ));
}

#[test]
fn load_symbols_stop_reconciles_and_resumes_as_modules_changed() {
    let mut backend = MockBackend::default().running();
    backend.modules_changed = true;
    backend.allow_breakpoints = true;
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    let id = session
        .add_symbol_breakpoint("driver!DeferredFn".into(), BreakpointConfig::default())
        .unwrap();
    assert!(
        session
            .breakpoints
            .list()
            .into_iter()
            .find(|breakpoint| breakpoint.id == id)
            .is_some_and(|breakpoint| !breakpoint.resolved)
    );

    let dtb = session.target.current_dtb();
    session.target.symbols.inject_source_lines_for_test(
        1,
        dtb,
        VirtAddr(0x1000),
        0x100,
        "driver.c",
        &[],
    );
    session
        .target
        .symbols
        .inject_module_for_test(1, Vec::new(), &[("DeferredFn", 0x10)]);

    let resolution = session.classify_stop_event(module_change_event()).unwrap();

    assert!(matches!(resolution, StopResolution::ModulesChanged));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    let breakpoint = session
        .breakpoints
        .list()
        .into_iter()
        .find(|breakpoint| breakpoint.id == id)
        .unwrap();
    assert!(breakpoint.resolved);
    assert_eq!(breakpoint.address, VirtAddr(0x1010));

    // The load was absorbed without halting; the host's next stop still
    // learns of it, once.
    assert!(session.refresh_modules_on_stop());
    assert!(!session.refresh_modules_on_stop());
}

#[test]
fn breakpoint_rewind_realigns_the_reporting_thread_without_thread_enumeration() {
    let mut backend = MockBackend::default();
    assert!(backend.thread_list().is_err(), "precondition");
    backend.set("rip", 0x1001);
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    rewind_thread_off_breakpoint(&mut backend, &register_map, &manager, Arch::Amd64);

    assert_eq!(backend.get("rip"), 0x1000);
}

#[test]
fn absorbed_software_breakpoint_invalidates_stopped_inspection() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1001);
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session.breakpoints.edit().set_pass_count(1, 2).unwrap();
    session.target.set_context_dtb_override(0x9000);
    let expected_dtb = session.target.kernel_dtb();

    assert!(matches!(
        session
            .classify_stop_event(breakpoint_event(0x1000))
            .unwrap(),
        StopResolution::Resumed
    ));
    assert!(session.backend.is_running());
    assert!(
        session.target.registers.is_none(),
        "running target must not expose stopped registers"
    );
    assert_eq!(session.target.current_dtb(), expected_dtb);
}

/// A breakpoint set where a one-shot breakpoint just fired, with the target
/// still halted at the hit, takes the site over: it is not refused as the
/// fired one's, which only the next resume would otherwise remove, and it
/// is the one listed.
#[test]
fn a_breakpoint_takes_over_the_site_of_a_fired_one_shot() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1001);
    let mut session = session_with_mock(backend);
    let once = BreakpointConfig {
        one_shot: true,
        ..BreakpointConfig::default()
    };
    let fired = session
        .add_breakpoint(VirtAddr(0x1000), None, once)
        .unwrap();
    let hit = session
        .classify_stop_event(breakpoint_event(0x1000))
        .unwrap();
    assert!(
        matches!(&hit, StopResolution::Breakpoint { breakpoint, .. } if breakpoint.id == fired),
        "precondition: the one-shot breakpoint stops"
    );

    let taken = session.add_breakpoint(VirtAddr(0x1000), None, BreakpointConfig::default());

    let taken = taken.unwrap();
    let listed: Vec<_> = session.breakpoints.list().iter().map(|bp| bp.id).collect();
    assert_eq!(listed, [taken]);
    assert!(!session.breakpoints.list()[0].one_shot);
}

/// A write over a planted breakpoint goes to the code the breakpoint
/// displaced: the site is lifted for the write and planted again after it,
/// whether or not the write lands (this memory refuses it), and a write
/// beside the site leaves it alone. Written over the planted instruction,
/// the write would be undone by the breakpoint's removal.
#[test]
fn a_write_over_a_breakpoint_lifts_and_replants_it() {
    let backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    };
    let sites = backend.site_log();
    let mut session = session_with_mock(backend);
    session
        .add_breakpoint(VirtAddr(0x1000), None, BreakpointConfig::default())
        .unwrap();

    let beside = session.write_memory(MemoryKind::Virtual, 0x1001, &[0x11]);
    let over = session.write_memory(MemoryKind::Virtual, 0xfff, &[0x11, 0x22, 0x33]);

    assert!(matches!(beside, Err(Error::ReadOnlyDump)), "{beside:?}");
    assert!(matches!(over, Err(Error::ReadOnlyDump)), "{over:?}");
    assert_eq!(
        *sites.lock(),
        [(0x1000, true), (0x1000, false), (0x1000, true)]
    );
    assert!(session.breakpoints.list()[0].enabled);
}

/// An expression reads the code under the session's sites as `db` does,
/// on every host: `eb nt!NtClose by(nt!NtClose)` read the planted `int3`
/// and wrote it in as the displaced code, which `bc` then put back for
/// good. A site taken out reads as what memory holds again.
#[test]
fn expressions_read_the_code_under_a_site() {
    // The breakpoint's and the trap's `int3`, as the target planted them.
    let mut memory = [0u8; 0x10];
    memory[..2].copy_from_slice(&[0xcc, 0x48]);
    memory[8..10].copy_from_slice(&[0xcc, 0x89]);
    let mut session = session_over_memory(0x1000, &memory);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    *session.bugcheck_trap.edit() = Some(TrapSite {
        address: VirtAddr(0x1008),
        original: vec![0x55],
    });
    let eval = |session: &Session, text: &str| Expr::eval(text, &session.target).unwrap().0;

    // `insert_for_test` displaced a 0x90.
    assert_eq!(eval(&session, "by(0x1000)"), 0x90);
    assert_eq!(eval(&session, "wo(0x1000)"), 0x4890);
    assert_eq!(eval(&session, "by(0x1001)"), 0x48);
    assert_eq!(eval(&session, "wo(0x1008)"), 0x8955);
    let mut bytes = [0u8; 2];
    session
        .target
        .read_masked(VirtAddr(0x1000), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0x90, 0x48]);

    let backend = session.backend.as_mut();
    session.breakpoints.edit().discard(backend, 1).unwrap();
    *session.bugcheck_trap.edit() = None;
    assert_eq!(eval(&session, "by(0x1000)"), 0xcc);
    assert_eq!(eval(&session, "by(0x1008)"), 0xcc);
}

/// A typed read (a `dt` field, a `dx` array element, an extension's struct
/// walk) sees the code under a planted site as `db` does, and the bytes
/// beside the site as memory holds them.
#[test]
fn typed_reads_see_the_code_under_a_site() {
    let mut memory = [0u8; 0x10];
    memory[..2].copy_from_slice(&[0xcc, 0x48]);
    let mut session = session_over_memory(0x1000, &memory);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    let byte = |offset| FieldInfo {
        offset,
        size: 1,
        type_data: ParsedType::Primitive("UCHAR".to_string()),
    };
    let layout = Arc::new(TypeInfo {
        name: "_CODE".to_string(),
        pointer_size: 8,
        size: 2,
        fields: [
            ("First".to_string(), byte(0)),
            ("Second".to_string(), byte(1)),
        ]
        .into_iter()
        .collect(),
    });
    let types = session.target.context_types();

    // Field reads, with the struct prefetched and without.
    let code = types.struct_with_layout(Arc::clone(&layout), VirtAddr(0x1000));
    assert_eq!(code.read_uint("First").unwrap(), 0x90);
    assert_eq!(code.read_uint("Second").unwrap(), 0x48);
    let code = code.prefetch();
    assert_eq!(code.read_field_bytes("First", 2).unwrap(), [0x90]);
    assert_eq!(code.read_uint("Second").unwrap(), 0x48);
    // An element of an array starting a byte earlier, the site in its
    // second field.
    let element = types.struct_with_layout(layout, VirtAddr(0xfff)).prefetch();
    assert_eq!(element.read_uint("Second").unwrap(), 0x90);
}

#[test]
fn absorbed_watchpoint_invalidates_stopped_inspection() {
    let mut backend = MockBackend::default();
    backend.set("dr6", 1);
    backend.set("rip", 0x1010);
    let mut session = session_with_mock(backend);
    *session.breakpoints.edit() = manager_with_hw(0, HwBreakpointAccess::Write, true);
    session.breakpoints.edit().set_pass_count(7, 2).unwrap();

    assert!(matches!(
        session.classify_stop_event(single_step_event()).unwrap(),
        StopResolution::Resumed
    ));
    assert!(session.backend.is_running());
    assert!(
        session.target.registers.is_none(),
        "running target must not expose stopped registers"
    );
}

fn deferred_symbol_breakpoint(session: &mut Session) -> u32 {
    let id = session
        .add_symbol_breakpoint("driver!DeferredFn".into(), BreakpointConfig::default())
        .unwrap();
    assert!(!breakpoint_by_id(session, id).resolved, "precondition");
    id
}

fn breakpoint_by_id(session: &Session, id: u32) -> BreakpointInfo {
    session
        .breakpoints
        .list()
        .into_iter()
        .find(|breakpoint| breakpoint.id == id)
        .unwrap()
        .clone()
}

/// Make `driver!DeferredFn` resolvable the way a symbol load that the session
/// did not perform itself would (background fetch, lazy frame load, attach).
fn publish_driver_symbols(session: &Session) {
    let dtb = session.target.current_dtb();
    session.target.symbols.inject_source_lines_for_test(
        1,
        dtb,
        VirtAddr(0x1000),
        0x100,
        "driver.c",
        &[],
    );
    session
        .target
        .symbols
        .inject_module_for_test(1, Vec::new(), &[("DeferredFn", 0x10)]);
}

#[test]
fn symbols_loaded_outside_a_stop_resolve_a_deferred_breakpoint_when_halted() {
    let backend = MockBackend {
        allow_breakpoints: true,
        ..Default::default()
    };
    let mut session = session_with_mock(backend);
    let id = deferred_symbol_breakpoint(&mut session);

    session.reconcile_breakpoints_if_symbols_changed();
    assert!(
        !breakpoint_by_id(&session, id).resolved,
        "resolved with nothing loaded"
    );

    publish_driver_symbols(&session);
    session.reconcile_breakpoints_if_symbols_changed();

    let breakpoint = breakpoint_by_id(&session, id);
    assert!(breakpoint.resolved);
    assert_eq!(breakpoint.address, VirtAddr(0x1010));
}

#[test]
fn symbols_loaded_while_running_resolve_a_deferred_breakpoint_at_the_next_stop() {
    let mut backend = MockBackend::default().running();
    backend.allow_breakpoints = true;
    backend.queue_interrupt(breakpoint_event(0x5000));
    let mut session = session_with_mock(backend);
    let id = deferred_symbol_breakpoint(&mut session);

    publish_driver_symbols(&session);
    session.reconcile_breakpoints_if_symbols_changed();
    assert!(
        !breakpoint_by_id(&session, id).resolved,
        "a site was installed into a running target"
    );

    // A plain break-in, not a module-change event.
    session.interrupt().unwrap();
    assert!(!session.backend.is_running());
    session.refresh_modules_on_stop();

    let breakpoint = breakpoint_by_id(&session, id);
    assert!(breakpoint.resolved);
    assert_eq!(breakpoint.address, VirtAddr(0x1010));
}

#[test]
fn breakpoint_rewind_leaves_an_unrelated_program_counter_alone() {
    let mut backend = MockBackend::default();
    backend.set("rip", 0x2001);
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    rewind_thread_off_breakpoint(&mut backend, &register_map, &manager, Arch::Amd64);

    assert_eq!(backend.get("rip"), 0x2001);
    assert_eq!(backend.writes, 0);
}

#[test]
fn a_target_owned_breakpoint_is_stepped_over_and_written_back() {
    let session = session_over_memory(0x1000, &[0u8; 0x80]);
    let mut backend = MockBackend::default().target_managed_sites();
    backend.allow_breakpoints = true;
    backend.set("rip", 0x1000);
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    let stepped = step_over_current_breakpoint(
        &mut backend,
        &register_map,
        &session.target,
        &mut manager,
        "p01.01",
    )
    .unwrap();

    assert_eq!(stepped, Some(RunPast::Reached));
    assert_eq!(backend.get("rip"), 0x1001);
    assert!(manager.list()[0].enabled);
    // The target dropped the entry when it reported the hit; the step
    // executes the displaced instruction and the site is written again.
    assert_eq!(
        *backend.site_writes.lock(),
        [(0x1000, false), (0x1000, true)]
    );
}

/// Under the Windows hypervisor a single step can finish inside the
/// hypervisor and leak its trap into Windows, so continuing from a hit is a
/// run of this vCPU alone to a temporary breakpoint on the next instruction.
#[test]
fn a_site_under_the_windows_hypervisor_is_run_past_without_a_step() {
    // mov rax, rbx (3 bytes) at the site.
    let mut code = [0x90u8; 0x20];
    code[..3].copy_from_slice(&[0x48, 0x89, 0xd8]);
    let session = session_over_memory(0x1000, &code);
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        lands_at: Some(0x1003),
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    let passed = step_over_current_breakpoint(
        &mut backend,
        &register_map,
        &session.target,
        &mut manager,
        "p01.01",
    )
    .unwrap();

    assert_eq!(passed, Some(RunPast::Reached));
    assert_eq!(backend.get("rip"), 0x1003);
    assert!(manager.list()[0].enabled);
    assert_eq!(
        *backend.site_writes.lock(),
        [
            (0x1000, false),
            (0x1003, true),
            (0x1003, false),
            (0x1000, true)
        ]
    );
}

/// A vCPU that never executes the instruction (it waits on a held one) must
/// not leave the temporary sites behind or the user's site lifted.
#[test]
fn a_site_that_cannot_be_run_past_is_rearmed_and_reported() {
    let mut code = [0x90u8; 0x20];
    code[..3].copy_from_slice(&[0x48, 0x89, 0xd8]);
    let session = session_over_memory(0x1000, &code);
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    backend.queue_interrupt(breakpoint_event(0x1000));
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    assert!(
        step_over_current_breakpoint(
            &mut backend,
            &register_map,
            &session.target,
            &mut manager,
            "p01.01",
        )
        .is_err()
    );
    assert!(manager.list()[0].enabled);
    assert_eq!(
        *backend.site_writes.lock(),
        [
            (0x1000, false),
            (0x1003, true),
            (0x1003, false),
            (0x1000, true)
        ]
    );
}

#[test]
fn successors_cover_both_branch_arms_and_resolve_returns_and_indirect_calls() {
    let mut memory = vec![0u8; 0x80];
    memory[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    memory[0x10] = 0xc3; // ret
    memory[0x20..0x23].copy_from_slice(&[0xff, 0x53, 0x08]); // call [rbx+8]
    memory[0x40..0x48].copy_from_slice(&0x2222u64.to_le_bytes());
    memory[0x58..0x60].copy_from_slice(&0x3333u64.to_le_bytes());
    let session = session_over_memory(0x1000, &memory);
    let mut backend = MockBackend::default();
    backend.set("rsp", 0x1040);
    backend.set("rbx", 0x1050);
    let register_map = backend.register_map().clone();
    let regs = backend.read_registers().unwrap();
    let successors =
        |rip| site_successors(&session.target, &register_map, "p01.01", &regs, rip, None).unwrap();

    assert_eq!(successors(0x1000), [0x1002, 0x1012]);
    assert_eq!(successors(0x1010), [0x2222]);
    assert_eq!(successors(0x1020), [0x3333]);
}

/// Transfers whose target is not a branch operand: `sysret` returns to RCX,
/// `iretq` pops an 8-byte RIP and a 64-bit-mode `retf` a 4-byte one, a far
/// `jmp [m16:32]` reads a 4-byte offset, and a hypercall and a user-mode
/// system call come back to the next instruction.
#[test]
fn successors_follow_privilege_and_far_transfers() {
    let mut memory = vec![0x90u8; 0x80];
    memory[..3].copy_from_slice(&[0x48, 0x0f, 0x07]); // sysretq
    memory[0x08..0x0a].copy_from_slice(&[0x48, 0xcf]); // iretq
    memory[0x10] = 0xcb; // retf
    memory[0x18..0x1b].copy_from_slice(&[0x0f, 0x01, 0xc1]); // vmcall
    memory[0x20..0x22].copy_from_slice(&[0xff, 0x2b]); // jmp far [rbx]
    memory[0x28..0x2a].copy_from_slice(&[0x0f, 0x05]); // syscall
    memory[0x30..0x32].copy_from_slice(&[0xcd, 0x2e]); // int 0x2e
    memory[0x40..0x48].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
    memory[0x50..0x58].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
    let session = session_over_memory(0x1000, &memory);
    let mut backend = MockBackend::default();
    backend.set("rsp", 0x1040);
    backend.set("rbx", 0x1050);
    backend.set("rcx", 0x7ff0_1234);
    let register_map = backend.register_map().clone();
    let regs = backend.read_registers().unwrap();
    let successors =
        |rip| site_successors(&session.target, &register_map, "p01.01", &regs, rip, None).unwrap();

    assert_eq!(successors(0x1000), [0x7ff0_1234]);
    assert_eq!(successors(0x1008), [0x1111_2222_3333_4444]);
    assert_eq!(successors(0x1010), [0x3333_4444]);
    assert_eq!(successors(0x1018), [0x101b]);
    assert_eq!(successors(0x1020), [0x7777_8888]);
    // A user-mode system call comes back to the next instruction.
    assert_eq!(successors(0x1028), [0x102a]);
    assert_eq!(successors(0x1030), [0x1032]);
}

fn stepping_session(code: &[u8], backend: MockBackend) -> Session {
    let mut session = session_over_memory(0x1000, code);
    session.backend = Box::new(backend);
    session.register_map = Arch::Amd64.register_map().clone();
    session
}

/// Where a step that ended as a plain step left its vCPU.
fn step_rip(session: &mut Session) -> u64 {
    match session.step().unwrap() {
        ContinueOutcome::Step { rip } => rip,
        other => panic!("the step ended on {other:?}"),
    }
}

/// A target that runs on after a step never reports it; Ctrl+C breaks in
/// and the step ends at that stop. The Ctrl+C stays raised for a loop of
/// steps around this one.
#[test]
fn ctrl_c_breaks_in_on_a_step_that_does_not_stop() {
    let mut backend = MockBackend {
        halts_only_on_interrupt: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let interrupts = backend.interrupts.clone();
    let mut session = stepping_session(&[0x90; 0x10], backend);
    session.target.interrupt.store(true, Ordering::SeqCst);

    assert_eq!(step_rip(&mut session), 0x1001);
    assert_eq!(interrupts.load(Ordering::Relaxed), 1);
    assert!(session.target.interrupt.load(Ordering::SeqCst));
}

/// The entries of one phase of a site log in a fixed order: the order a
/// step visits its successors in is not part of its contract.
fn sorted<T: Copy + Ord>(entries: &[T]) -> Vec<T> {
    let mut entries = entries.to_vec();
    entries.sort_unstable();
    entries
}

/// Under the Windows hypervisor a step is this vCPU run alone to temporary
/// sites on every successor (both arms of a branch), lifted afterwards.
#[test]
fn a_step_under_the_windows_hypervisor_runs_the_vcpu_alone_to_every_successor() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        lands_at: Some(0x1012),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let mut session = stepping_session(&code, backend);

    assert_eq!(step_rip(&mut session), 0x1012);
    let sites = sites.lock();
    assert_eq!(sites.len(), 4, "{sites:?}");
    assert_eq!(sorted(&sites[..2]), [(0x1002, true), (0x1012, true)]);
    assert_eq!(sorted(&sites[2..]), [(0x1002, false), (0x1012, false)]);
    assert!(hardware.lock().is_empty());
}

/// A vCPU run alone that reaches none of its successors before the timeout
/// took an interrupt, and the handler waits on a held vCPU: the others are
/// let run so it can finish. One still in the handler after that stops
/// there and says why; one that reached a successor says nothing.
#[test]
fn a_step_diverted_into_an_interrupt_handler_says_so() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    for (lands_at, diverted) in [(0x1030, true), (0x1012, false)] {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            single_step_unsafe: true,
            halts_only_on_interrupt: true,
            lands_at: Some(lands_at),
            released_to: Some(lands_at),
            one_vcpu: true,
            ..MockBackend::default()
        };
        backend.set("rip", 0x1000);
        let mut session = stepping_session(&code, backend);

        assert_eq!(step_rip(&mut session), lands_at);
        let notices = session.take_notices();
        assert_eq!(!notices.is_empty(), diverted, "{notices:?}");
    }
}

/// A handler that hits a breakpoint while the others run stops the step's
/// vCPU on it: the step ends there at once, rather than letting them run
/// again until the release budget is spent.
#[test]
fn a_step_whose_handler_stops_on_a_breakpoint_ends_there() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        lands_at: Some(0x1030),
        released_to: Some(0x1030),
        released_stop_by: Some("p01.01"),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let continues = Arc::clone(&backend.continues);
    let mut session = stepping_session(&code, backend);
    session.current_thread = "p01.01".into();

    assert_eq!(step_rip(&mut session), 0x1030);
    assert!(!session.take_notices().is_empty());
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// Another vCPU stopped on a site traps there again each time it is
/// resumed, so every run that resumes it ends at once. The step's vCPU,
/// waiting in a handler, gets its time in runs that hold that vCPU, and
/// the runs between still resume it: its handler can wait on that vCPU
/// taking an interrupt (here, being resumed `resumes` times).
#[test]
fn a_vcpu_parked_on_a_site_is_held_for_every_other_release_run() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    for resumes in [1, 3] {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            single_step_unsafe: true,
            halts_only_on_interrupt: true,
            lands_at: Some(0x1030),
            released_to: Some(0x1012),
            parked_vcpu: Some(("p01.02", 0x1020)),
            freed_after_resumes: resumes,
            one_vcpu: true,
            ..MockBackend::default()
        };
        backend.set("rip", 0x1000);
        let parked_resumes = Arc::clone(&backend.parked_resumes);
        let mut session = stepping_session(&code, backend);
        session.current_thread = "p01.01".into();

        assert_eq!(step_rip(&mut session), 0x1012, "freed after {resumes}");
        assert!(session.take_notices().is_empty());
        assert_eq!(parked_resumes.load(Ordering::Relaxed), resumes);
    }
}

/// The others are let run until the runs themselves have taken the release
/// budget: checks between runs that take as long, as the first one to find
/// a vCPU in the Windows hypervisor does, leave the handler the runs it
/// needs to finish, rather than ending the step in it.
#[test]
fn slow_checks_between_release_runs_leave_the_handler_its_runs() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let in_handler = Landing {
        rip: 0x1030,
        rsp: 0,
        ethread: 0,
    };
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        lands_at: Some(0x1030),
        schedule: VecDeque::from([in_handler, in_handler]),
        released_to: Some(0x1012),
        one_vcpu: true,
        register_read_delay: RELEASE_BUDGET,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut session = stepping_session(&code, backend);

    assert_eq!(step_rip(&mut session), 0x1012);
    assert!(session.take_notices().is_empty());
}

/// Under the Windows hypervisor, p01.01 run alone past `je +0x10` at 0x1000
/// waits in a handler at 0x1030 on the other vCPUs, and every run of them
/// all ends with a hit on write watchpoint #7 on 0x2000..0x2004: p01.02's
/// own stop, or with `stop_by` `None`, the stop that answers the break-in.
fn watched_release_session(stop_by: Option<&'static str>) -> (Session, Arc<AtomicUsize>) {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        lands_at: Some(0x1030),
        released_to: Some(0x1030),
        released_stop_by: stop_by,
        released_watch: Some(0x2002),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let continues = Arc::clone(&backend.continues);
    let mut session = stepping_session(&code, backend);
    session.current_thread = "p01.01".into();
    session.breakpoints.edit().insert_for_test(
        7,
        VirtAddr(0x2000),
        true,
        Some(HardwareBreakpoint {
            access: HwBreakpointAccess::Write,
            len: 4,
            slot: 0,
        }),
    );
    (session, continues)
}

/// A watchpoint another vCPU hits while a step waits on them is the step's
/// stop, with the target halted at it. Resumed with the next run, that
/// vCPU would not stop on it again (a watchpoint traps after the access),
/// and the hit was lost.
#[test]
fn a_watchpoint_hit_while_a_step_waits_on_the_others_is_the_steps_stop() {
    let (mut session, continues) = watched_release_session(Some("p01.02"));

    let outcome = session.step().unwrap();
    assert!(
        matches!(outcome, ContinueOutcome::Breakpoint { id: 7, .. }),
        "{outcome:?}"
    );
    assert_eq!(session.current_thread, "p01.02");
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A watchpoint's stop that answers the break-in ending a run, having come
/// first, is kept like one that ended the run itself.
#[test]
fn a_watchpoint_hit_that_answers_a_release_break_in_is_the_steps_stop() {
    let (mut session, continues) = watched_release_session(None);

    let outcome = session.step().unwrap();
    assert!(
        matches!(outcome, ContinueOutcome::Breakpoint { id: 7, .. }),
        "{outcome:?}"
    );
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A hit its watchpoint declines ends the step where the step's vCPU waits,
/// as a diverted step, rather than resuming past the hit as a run does.
#[test]
fn a_declined_watchpoint_hit_while_a_step_waits_ends_the_step_where_it_is() {
    let (mut session, continues) = watched_release_session(Some("p01.02"));
    session.breakpoints.edit().set_pass_count(7, 2).unwrap();

    assert_eq!(step_rip(&mut session), 0x1030);
    assert_eq!(session.current_thread, "p01.01");
    assert!(!session.take_notices().is_empty());
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A resume from a breakpoint first runs its vCPU past the site. A
/// watchpoint another vCPU hits meanwhile is the stop the resume reports,
/// with nothing run since: a walk following a thread waits on such a hit.
#[test]
fn a_watchpoint_hit_while_a_resume_leaves_its_site_is_the_next_stop() {
    let (mut session, continues) = watched_release_session(Some("p01.02"));
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);

    let outcome = session
        .continue_stop(
            ContinueDisposition::Handled,
            &Cancel::within(Duration::from_secs(1)),
        )
        .unwrap();
    assert!(
        matches!(outcome, ContinueOutcome::Breakpoint { id: 7, .. }),
        "{outcome:?}"
    );
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A resume with a stop kept reports that stop with nothing run first: no
/// vCPU steps off the site it is on, a run that would take the kept stop
/// for its own and lose it.
#[test]
fn a_resume_with_a_stop_kept_reports_it_without_leaving_a_site() {
    let mut kept = breakpoint_event(0x1030);
    kept.thread_id = Some("p01.02".into());
    kept.watchpoint_address = Some(0x2002);
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        lands_at: Some(0x1001),
        one_vcpu: true,
        kept: Some(kept),
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let sites = Arc::clone(&backend.site_writes);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session.current_thread = "p01.01".into();
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session.breakpoints.edit().insert_for_test(
        7,
        VirtAddr(0x2000),
        true,
        Some(HardwareBreakpoint {
            access: HwBreakpointAccess::Write,
            len: 4,
            slot: 0,
        }),
    );

    let outcome = session
        .continue_stop(
            ContinueDisposition::Handled,
            &Cancel::within(Duration::from_secs(1)),
        )
        .unwrap();
    assert!(
        matches!(outcome, ContinueOutcome::Breakpoint { id: 7, .. }),
        "{outcome:?}"
    );
    // A run past the `nop` at 0x1000 would mark its successor.
    assert!(
        !sites.lock().iter().any(|&(address, _)| address == 0x1001),
        "{:?}",
        sites.lock()
    );
}

/// A handler that finishes once the others run returns to the instruction
/// it interrupted, which is then run past alone again: the step completes
/// at a successor, with the instruction marked meanwhile and every site
/// lifted after.
#[test]
fn a_step_whose_handler_returns_once_the_others_run_completes() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        landings: VecDeque::from([0x1030]),
        lands_at: Some(0x1002),
        released_to: Some(0x1000),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let sites = backend.site_writes.clone();
    let mut session = stepping_session(&code, backend);

    assert_eq!(step_rip(&mut session), 0x1002);
    assert!(session.take_notices().is_empty());
    let sites = sites.lock();
    assert_eq!(sites.len(), 6, "{sites:?}");
    assert_eq!(sorted(&sites[..2]), [(0x1002, true), (0x1012, true)]);
    assert_eq!(sites[2..4], [(0x1000, true), (0x1000, false)]);
    assert_eq!(sorted(&sites[4..]), [(0x1002, false), (0x1012, false)]);
}

/// A walk started on an instruction that matches executes it first, as
/// WinDbg's `pc` on a call does, so repeating the walk moves on.
#[test]
fn a_walk_started_on_a_match_executes_it_first() {
    let mut backend = MockBackend {
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut session = stepping_session(&[0x90; 0x40], backend);

    let outcome = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip != 0x1001)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
}

/// Stepping on from a diverted step steps the handler's wait, which no held
/// vCPU ends: a step loop stops where the step landed instead of stepping
/// that wait to its limit.
#[test]
fn step_loops_stop_at_a_diverted_step() {
    let code = [0x90u8; 0x40]; // no call for `until="call"` to find
    let diverted_session = || {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            single_step_unsafe: true,
            halts_only_on_interrupt: true,
            lands_at: Some(0x1030),
            released_to: Some(0x1030),
            one_vcpu: true,
            ..MockBackend::default()
        };
        backend.set("rip", 0x1000);
        stepping_session(&code, backend)
    };

    let mut session = diverted_session();
    let outcome = session
        .step_until(StepMode::Into, 1_000, &Cancel::NEVER, |_, flow| {
            flow == crate::base::disasm::ControlFlow::Call
        })
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1030 }));

    let trace = diverted_session()
        .trace_calls(1_000, &Cancel::NEVER)
        .unwrap();
    assert_eq!(trace.end, CallTraceEnd::Diverted);
    assert_eq!(trace.instructions, 0);
}

/// Resuming from a hit, the vCPU run past the site alone can take an
/// interrupt on it first, leaving the processor's return frame on its stack.
/// When the handler returns there, the re-armed site traps that same
/// execution again: that is absorbed once, and the next hit from the same
/// stack is a new one.
#[test]
fn a_hit_interrupted_on_its_site_is_reported_once() {
    // mov rax, rbx at the site; a stack below it.
    let mut memory = [0x90u8; 0x100];
    memory[..3].copy_from_slice(&[0x48, 0x89, 0xd8]);
    let rsp = 0x1088;
    // The interrupt frame is pushed below the 16-byte-aligned RSP: RIP,
    // CS, RFLAGS, RSP, SS.
    for (index, value) in [0x1000, 0x10, 0x202, rsp, 0x18].into_iter().enumerate() {
        let at = 0x80 - 40 + index * 8;
        memory[at..at + 8].copy_from_slice(&u64::to_le_bytes(value));
    }
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        landings: VecDeque::from([0x1030]),
        lands_at: Some(0x1003),
        released_to: Some(0x1030),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    backend.set("rsp", rsp);
    let mut session = stepping_session(&memory, backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session.current_thread = "p01.01".into();

    // The resume diverts: the vCPU stays in the handler.
    session.resume().unwrap();
    session.backend.interrupt().unwrap();
    let returned = |session: &mut Session| {
        let backend = session.backend.as_mut();
        let mut regs = backend.read_registers().unwrap();
        session
            .register_map
            .write_u64("rip", &mut regs, 0x1000)
            .unwrap();
        session
            .register_map
            .write_u64("rsp", &mut regs, rsp)
            .unwrap();
        backend.write_registers(&regs).unwrap();
        session.resolve_breakpoint_stop(0x1000, 0).unwrap()
    };
    assert!(matches!(
        returned(&mut session),
        BreakpointStopAction::Resumed
    ));
    session.backend.interrupt().unwrap();
    assert!(matches!(
        returned(&mut session),
        BreakpointStopAction::Hit { .. }
    ));
}

/// A hypercall breakpoint's hit whose caller cannot be told (here no
/// hypervisor can be walked) stops and is counted rather than being
/// declined: a filter must never lose a hit silently.
#[test]
fn a_hypercall_breakpoint_stops_when_its_caller_is_unknown() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    let filter = HypercallFilter {
        code: 0x000b,
        partition: Some(0x7),
        vp: Some(1),
    };
    let id = session
        .add_breakpoint(
            VirtAddr(0x1000),
            None,
            BreakpointConfig {
                hypercall: Some(filter),
                ..BreakpointConfig::default()
            },
        )
        .unwrap();
    session.current_thread = "p01.01".into();
    match session.resolve_breakpoint_stop(0x1000, 0).unwrap() {
        BreakpointStopAction::Hit { breakpoint, .. } => assert_eq!(breakpoint.id, id),
        _ => panic!("the hit was declined"),
    }
    assert_eq!(session.breakpoint(id).unwrap().hit_count, 1);
}

/// A backend whose debug registers trap inside the guest (KD) cannot stop
/// in the Windows hypervisor, so a hypercall breakpoint is refused there
/// rather than set to never fire.
#[test]
fn a_hypercall_breakpoint_needs_debug_registers_the_host_programs() {
    let backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    let filter = HypercallFilter {
        code: 0x000b,
        partition: None,
        vp: None,
    };
    assert!(
        session
            .add_hypercall_breakpoint(filter, BreakpointConfig::default())
            .is_err()
    );
    assert!(session.list_breakpoints().is_empty());
}

/// A hit the SDK's `when=` callback declines on another vCPU than a step's
/// is stepped off its site, and the step's vCPU is selected again; a hit on
/// the step's own vCPU is left for the step to go on from.
#[test]
fn a_declined_hit_on_another_vcpu_hands_the_step_back() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    let rip = |session: &mut Session| {
        let regs = session.backend.read_registers().unwrap();
        session.register_map.read_u64("rip", &regs).unwrap()
    };

    session.current_thread = "p01.01".into();
    session.pass_declined_hit("p01.01").unwrap();
    assert_eq!(rip(&mut session), 0x1000);

    session.current_thread = "p01.02".into();
    session.pass_declined_hit("p01.01").unwrap();
    assert_eq!(session.current_thread, "p01.01");
    assert_eq!(rip(&mut session), 0x1001);
}

/// Where only the vCPU that reported a stop can step (ARM64 KD), a step
/// another vCPU's hit came before stays armed: declined, the hit is stepped
/// past and the target resumed, and the armed step is the step's stop. A
/// new step of the stepped vCPU would be refused while the other one holds
/// the target. The armed step is the processor's: taken by a thread switched
/// in meanwhile, it ends the step diverted, where that thread is.
#[test]
fn a_step_another_vcpus_declined_hit_came_before_goes_on_by_resuming() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    for (finished_in, diverted) in [(WALKED, false), (OTHER, true)] {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            one_vcpu: true,
            stopping_processor_only: true,
            step_cut_short_by: Some((
                "p01.02",
                1,
                at(0x1020, 0x8000, OTHER),
                at(0x1001, 0x2000, finished_in),
            )),
            ..MockBackend::default()
        };
        backend.land(at(0x1000, 0x2000, WALKED));
        let (steps, continues) = (Arc::clone(&backend.steps), Arc::clone(&backend.continues));
        let mut session = session_running_code(&[0x90u8; 0x40], backend);
        session
            .breakpoints
            .edit()
            .insert_for_test(1, VirtAddr(0x1020), true, None);

        let hit = session.step().unwrap();
        assert!(matches!(hit, ContinueOutcome::Breakpoint { .. }), "{hit:?}");
        session.decline(Motion::Step, "p01.01").unwrap();
        let stepped = session.step().unwrap();

        assert!(
            matches!(stepped, ContinueOutcome::Step { rip: 0x1001 }),
            "{stepped:?}"
        );
        // The step itself, then the hit's vCPU off its site; none after.
        assert_eq!(steps.load(Ordering::Relaxed), 2);
        assert_eq!(continues.load(Ordering::Relaxed), 1);
        assert_eq!(session.current_thread, "p01.01");
        let noted = session
            .take_notices()
            .iter()
            .any(|notice| notice.text.contains("did not reach the next instruction"));
        assert_eq!(noted, diverted, "{finished_in:#x}");
    }
}

/// A walk with no sites to follow its thread to (its instruction's
/// successors not known), resumed after such a declined hit, finishes the
/// armed step first. Taken by a thread switched in meanwhile, that step ends
/// the walk diverted, where that thread is, rather than walking on in it.
#[test]
fn a_resumed_walk_ends_where_its_armed_step_was_diverted() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let until = |ip, _| ip == 0x1002;
    for (finished_in, ended_at, diverted) in [(WALKED, 0x1002, false), (OTHER, 0x1001, true)] {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            one_vcpu: true,
            stopping_processor_only: true,
            step_cut_short_by: Some((
                "p01.02",
                1,
                at(0x1020, 0x8000, OTHER),
                at(0x1001, 0x2000, finished_in),
            )),
            ..MockBackend::default()
        };
        backend.land(at(0x1000, 0x2000, WALKED));
        let mut session = session_running_code(&[0x90u8; 0x40], backend);
        session
            .breakpoints
            .edit()
            .insert_for_test(1, VirtAddr(0x1020), true, None);

        let hit = session
            .step_until(StepMode::Into, 16, &Cancel::NEVER, until)
            .unwrap();
        assert!(matches!(hit, ContinueOutcome::Breakpoint { .. }), "{hit:?}");
        // The mock's nops have successors; the walk is left as one whose
        // instruction had none.
        session.pending_walk = Some(PendingWalk {
            vcpu: "p01.01".into(),
            sites: Vec::new(),
        });
        session.take_notices();
        let outcome = session
            .resume_step_until(StepMode::Into, 16, &Cancel::NEVER, until)
            .unwrap();

        assert!(
            matches!(outcome, ContinueOutcome::Step { rip } if rip == ended_at),
            "{finished_in:#x}: {outcome:?}"
        );
        let noted = session
            .take_notices()
            .iter()
            .any(|notice| notice.text.contains("did not reach the next instruction"));
        assert_eq!(noted, diverted, "{finished_in:#x}");
    }
}

/// An ARM64 walk knows where its thread goes on, as an x86 one does: resumed
/// after another vCPU's declined hit came before its step, it runs to the
/// stepped `bl`'s target in the walked thread, at no lower a stack, rather
/// than finishing the armed step, which a thread the processor switched to
/// takes.
#[test]
fn an_arm64_walk_follows_its_thread_past_a_step_another_vcpus_hit_came_before() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    // bl 0x1020, then nops.
    let mut code = [0u8; 0x40];
    for (slot, word) in code
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(std::iter::once(0x9400_0008u32).chain(std::iter::repeat(0xd503_201f)))
    {
        *slot = word.to_le_bytes();
    }
    let mut backend = MockBackend {
        register_map: Arch::Arm64.register_map().clone(),
        regs: vec![0; arm64::REGISTER_BUFFER_SIZE],
        allow_breakpoints: true,
        one_vcpu: true,
        stopping_processor_only: true,
        step_cut_short_by: Some((
            "p01.02",
            1,
            at(0x1038, 0x8000, OTHER),
            at(0x1030, 0x9000, OTHER),
        )),
        schedule: [
            at(0x1020, 0x1ff0, WALKED),
            at(0x1020, 0x2000, OTHER),
            at(0x1020, 0x2000, WALKED),
        ]
        .into(),
        ..MockBackend::default()
    };
    backend.land(at(0x1000, 0x2000, WALKED));
    let (threads, continues) = (Arc::clone(&backend.threads), Arc::clone(&backend.continues));
    let mut session = session_over_arm64_memory(0x1000, &code);
    session.register_map = backend.register_map.clone();
    session.backend = Box::new(backend);
    session.target.test_current_threads = Some(threads);
    session.current_thread = "p01.01".into();
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1038), true, None);
    let until = |ip, _| ip == 0x1020;

    let hit = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, until)
        .unwrap();
    assert!(matches!(hit, ContinueOutcome::Breakpoint { .. }), "{hit:?}");
    let outcome = session
        .resume_step_until(StepMode::Into, 16, &Cancel::NEVER, until)
        .unwrap();

    assert!(
        matches!(outcome, ContinueOutcome::Step { rip: 0x1020 }),
        "{outcome:?}"
    );
    // The armed step's stop, then the deeper call, the other thread, and
    // the walked one.
    assert_eq!(continues.load(Ordering::Relaxed), 4);
}

/// A walk another stop ended while it ran over a call goes on by finishing
/// that run, not by walking from wherever the processor is now (another
/// thread's code after a context switch); a fresh walk forgets it. One a
/// hit on another vCPU ended goes on from the walk's vCPU, which the hit's
/// is stepped off.
#[test]
fn a_resumed_walk_finishes_the_run_it_was_waiting_on() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        released_to: Some(0x1010),
        ..MockBackend::default()
    };
    backend.set("rip", 0x1020);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session.current_thread = "p01.01".into();
    let pending = |sites| {
        Some(PendingWalk {
            vcpu: "p01.01".into(),
            sites,
        })
    };
    session.pending_walk = pending(vec![(VirtAddr(0x1010), None)]);

    let outcome = session
        .resume_step_until(StepMode::Over, 16, &Cancel::NEVER, |ip, _| ip == 0x1010)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1010 }));
    assert!(session.pending_walk.is_none());

    session.pending_walk = pending(vec![(VirtAddr(0x1030), None)]);
    let outcome = session
        .step_until(StepMode::Over, 16, &Cancel::NEVER, |ip, _| ip == 0x1011)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1011 }));
    assert!(session.pending_walk.is_none());

    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1011), true, None);
    session.current_thread = "p01.02".into();
    session.pending_walk = pending(Vec::new());
    let outcome = session
        .resume_step_until(StepMode::Over, 16, &Cancel::NEVER, |ip, _| ip == 0x1012)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1012 }));
    assert_eq!(session.current_thread, "p01.01");
}

const WALKED: u64 = 0xffff_8000_0000_a000;
const OTHER: u64 = 0xffff_8000_0000_b000;

/// A walk over `nops` from 0x1000 on processor 0 (`p01.01`), stack at
/// 0x2000, running thread [`WALKED`]; steps and runs land per the lists.
fn walk_session(steps: &[Landing], runs: &[Landing]) -> (Session, Arc<AtomicUsize>) {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        step_landings: steps.iter().copied().collect(),
        schedule: runs.iter().copied().collect(),
        ..MockBackend::default()
    };
    backend.land(Landing {
        rip: 0x1000,
        rsp: 0x2000,
        ethread: WALKED,
    });
    let continues = Arc::clone(&backend.continues);
    (session_running_code(&[0x90u8; 0x40], backend), continues)
}

/// A step that an interrupt switched to another thread goes on in the
/// walked thread: the walk runs until that thread executes past the
/// instruction at the stack it left, passing other threads and deeper
/// calls of the same code there.
#[test]
fn a_walk_follows_its_thread_past_a_step_that_switched_it_out() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) = walk_session(
        &[at(0x1030, 0x8000, OTHER)],
        &[
            at(0x1001, 0x1ff8, WALKED),
            at(0x1001, 0x2000, OTHER),
            at(0x1001, 0x2000, WALKED),
        ],
    );

    let outcome = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip == 0x1002)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
    assert_eq!(continues.load(Ordering::Relaxed), 3);
}

/// A call trace follows its thread past a step that switched it out, as a
/// walk does, rather than ending there.
#[test]
fn a_call_trace_follows_its_thread_past_a_step_that_switched_it_out() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) = walk_session(
        &[at(0x1030, 0x8000, OTHER)],
        &[at(0x1001, 0x2000, OTHER), at(0x1001, 0x2000, WALKED)],
    );

    let trace = session.trace_calls(2, &Cancel::NEVER).unwrap();
    assert_eq!(trace.end, CallTraceEnd::Limit);
    assert_eq!(trace.instructions, 2);
    assert_eq!(continues.load(Ordering::Relaxed), 2);
}

/// A call trace that ends at a user breakpoint runs its action, as a step
/// or a run that stops there does; the trace stays ended even when the
/// action asks to resume.
#[test]
fn a_call_trace_ending_at_a_breakpoint_runs_its_action() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) = walk_session(&[at(0x1001, 0x2000, WALKED)], &[]);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1001), true, None);
    session
        .breakpoints
        .edit()
        .set_action(1, Some("log".into()))
        .unwrap();
    let log = recording(&mut session, true);

    let trace = session.trace_calls(100, &Cancel::NEVER).unwrap();
    assert_eq!(trace.end, CallTraceEnd::Breakpoint);
    assert_eq!(*log.lock(), ["action log"]);
    assert_eq!(
        continues.load(Ordering::Relaxed),
        0,
        "the action's resume ran"
    );
}

/// A call trace whose thread never reaches the instruction a step left it
/// short of, while other threads keep reaching it first, ends as
/// interrupted when its time limit runs out instead of waiting on the
/// thread forever.
#[test]
fn a_call_trace_ends_at_its_time_limit_while_other_threads_take_its_site() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) = walk_session(
        &[at(0x1030, 0x8000, OTHER)],
        &[at(0x1001, 0x2000, OTHER); 64],
    );

    let started = Instant::now();
    let trace = session
        .trace_calls(100, &Cancel::within(Duration::from_millis(300)))
        .unwrap();
    assert_eq!(trace.end, CallTraceEnd::Interrupted);
    assert_eq!(trace.instructions, 0);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(continues.load(Ordering::Relaxed) > 0);
}

/// A step that reached the next instruction stays in the walk even when it
/// made another thread current, as the instruction that switches does, while
/// the stack is still the walked thread's.
#[test]
fn a_walk_step_that_reached_its_successor_is_not_followed() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) = walk_session(&[at(0x1001, 0x2000, OTHER)], &[]);
    session.target.test_thread_stacks =
        HashMap::from([(VirtAddr(WALKED), (VirtAddr(0x1000), VirtAddr(0x3000)))]);

    let outcome = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip == 0x1002)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
    assert_eq!(continues.load(Ordering::Relaxed), 0);
}

/// A step that reached the next instruction on another thread's stack ran
/// that thread: NT loaded it there, and the walked thread goes on at the
/// instruction when it is switched back in, so the walk follows it rather
/// than stepping the other thread.
#[test]
fn a_walk_step_that_reached_its_successor_on_another_stack_is_followed() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, continues) =
        walk_session(&[at(0x1001, 0x8000, OTHER)], &[at(0x1001, 0x2000, WALKED)]);
    session.target.test_thread_stacks =
        HashMap::from([(VirtAddr(WALKED), (VirtAddr(0x1000), VirtAddr(0x3000)))]);

    let outcome = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip == 0x1002)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A step whose trap the walked thread took on another vCPU, which it was
/// switched out to with the trap flag set, completed: it is at the next
/// instruction there, and the walk goes on from it. Followed instead, the
/// run to the next instruction would step the thread off it, and wait for
/// it to get there again.
#[test]
fn a_walk_step_its_thread_completed_on_another_vcpu_is_not_followed() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        step_landings: VecDeque::from([Landing {
            rip: 0x1001,
            rsp: 0x2000,
            ethread: WALKED,
        }]),
        step_reported_by: Some(("p01.02", 1)),
        ..MockBackend::default()
    };
    backend.land(Landing {
        rip: 0x1000,
        rsp: 0x2000,
        ethread: WALKED,
    });
    let continues = Arc::clone(&backend.continues);
    let mut session = session_running_code(&[0x90u8; 0x40], backend);

    let outcome = session
        .step_until(
            StepMode::Into,
            16,
            &Cancel::within(Duration::from_millis(300)),
            |ip, _| ip == 0x1002,
        )
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
    assert_eq!(continues.load(Ordering::Relaxed), 0);
}

/// A hit stepped over where single steps are unsafe runs its vCPU alone
/// with the site lifted, at `rip` 0x1000 in [`WALKED`] on stack 0x2000. A
/// debug-register keeper marks the site meanwhile.
fn kept_step_over(alone: &[Landing]) -> (Session, HardwareWrites) {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        one_vcpu: true,
        lands_at: Some(0x1001),
        alone_schedule: alone.iter().copied().collect(),
        ..MockBackend::default()
    };
    backend.land(Landing {
        rip: 0x1000,
        rsp: 0x2000,
        ethread: WALKED,
    });
    let (hardware, threads) = (backend.hardware_writes.clone(), backend.threads.clone());
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session.target.test_current_threads = Some(threads);
    session.current_thread = "p01.01".into();
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    (session, hardware)
}

/// Another thread the stepping vCPU switches to stops on the lifted site,
/// rather than running through it unseen: the step-over ends there, and
/// that thread's hit is the planted breakpoint's once it is back.
#[test]
fn a_thread_that_reaches_a_site_while_it_is_stepped_over_stops_there() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, hardware) = kept_step_over(&[at(0x1000, 0x8000, OTHER)]);

    let stepped = session.step_over_site_at_pc().unwrap();
    assert_eq!(stepped, Some(RunPast::Diverted));
    assert_eq!(*hardware.lock(), [(0, Some(0x1000)), (0, None)]);
}

/// The stepping execution back on the kept site (it took an interrupt
/// first) is resumed past it with `RF` set, not taken for another thread.
#[test]
fn a_step_over_back_on_its_kept_site_goes_on_past_it() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, hardware) = kept_step_over(&[at(0x1000, 0x2000, WALKED)]);

    let stepped = session.step_over_site_at_pc().unwrap();
    assert_eq!(stepped, Some(RunPast::Reached));
    assert_eq!(*hardware.lock(), [(0, Some(0x1000)), (0, None)]);
    let registers = session.backend.read_registers().unwrap();
    let eflags = session.register_map.read_u64("eflags", &registers).unwrap();
    assert_ne!(eflags & (1 << 16), 0, "resumed on the kept site without RF");
}

/// A walk whose step ended on a breakpoint in another thread surfaces it;
/// resumed past it, it goes on where the walked thread executes past the
/// instruction.
#[test]
fn a_walk_resumed_past_a_hit_in_another_thread_goes_on_in_its_own() {
    let at = |rip, rsp, ethread| Landing { rip, rsp, ethread };
    let (mut session, _) = walk_session(
        &[at(0x1030, 0x8000, OTHER)],
        &[at(0x1001, 0x2000, OTHER), at(0x1001, 0x2000, WALKED)],
    );
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1030), true, None);

    let outcome = session
        .step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip == 0x1002)
        .unwrap();
    assert!(matches!(
        outcome,
        ContinueOutcome::Breakpoint { rip: 0x1030, .. }
    ));
    let outcome = session
        .resume_step_until(StepMode::Into, 16, &Cancel::NEVER, |ip, _| ip == 0x1002)
        .unwrap();
    assert!(matches!(outcome, ContinueOutcome::Step { rip: 0x1002 }));
}

/// A walk its timeout cuts short in a run (over a call here) ends where the
/// break-in caught the vCPU, as an interrupt's stop: not as a step, which
/// names an instruction the walk was after. Under VBS the break-in can
/// catch the vCPU in the Windows hypervisor, where no step goes on.
#[test]
fn a_walk_its_timeout_cuts_short_in_a_run_ends_as_an_interrupt() {
    let mut code = [0x90u8; 0x40];
    code[..5].copy_from_slice(&[0xe8, 0x1b, 0x00, 0x00, 0x00]); // call 0x1020
    let break_in = StopEvent {
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        break_in: true,
        ..single_step_event()
    };
    let mut backend = MockBackend {
        allow_breakpoints: true,
        halts_only_on_interrupt: true,
        one_vcpu: true,
        interrupt_events: VecDeque::from([break_in]),
        schedule: VecDeque::from([Landing {
            rip: 0x1020,
            rsp: 0x1ff8,
            ethread: WALKED,
        }]),
        ..MockBackend::default()
    };
    backend.land(Landing {
        rip: 0x1000,
        rsp: 0x2000,
        ethread: WALKED,
    });
    let threads = Arc::clone(&backend.threads);
    let mut session = stepping_session(&code, backend);
    session.target.test_current_threads = Some(threads);
    session.current_thread = "p01.01".into();

    let outcome = session
        .step_until(
            StepMode::Over,
            16,
            &Cancel::within(Duration::from_millis(50)),
            |ip, _| ip == 0x1010,
        )
        .unwrap();
    assert!(
        matches!(
            outcome,
            ContinueOutcome::Stopped {
                rip: 0x1020,
                exception_code: None,
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// The stack an instruction can leave is bounded below by what it pushes or
/// subtracts, and unknown when it switches stacks or sets the pointer.
#[test]
fn a_stack_floor_is_the_lowest_stack_an_instruction_leaves() {
    let floor = |bitness, bytes: &[u8]| {
        let instruction = Decoder::new(bitness, bytes, DecoderOptions::NONE).decode();
        stack_floor(&instruction, 0x1000)
    };
    assert_eq!(floor(64, &[0x90]), Some(0x1000)); // nop
    assert_eq!(floor(64, &[0x48, 0x8b, 0x44, 0x24, 0x08]), Some(0x1000)); // mov rax, [rsp+8]
    assert_eq!(floor(64, &[0x55]), Some(0xff8)); // push rbp
    assert_eq!(floor(64, &[0xe8, 0, 0, 0, 0]), Some(0xff8)); // call
    assert_eq!(floor(64, &[0xc3]), Some(0x1000)); // ret
    assert_eq!(floor(64, &[0x48, 0x83, 0xec, 0x30]), Some(0xfd0)); // sub rsp, 0x30
    assert_eq!(floor(64, &[0x48, 0x81, 0xec, 0, 1, 0, 0]), Some(0xf00)); // sub rsp, 0x100
    assert_eq!(floor(64, &[0x48, 0x83, 0xc4, 0xe0]), Some(0xfe0)); // add rsp, -0x20
    assert_eq!(floor(64, &[0x48, 0x83, 0xc4, 0x20]), Some(0x1000)); // add rsp, 0x20
    assert_eq!(floor(32, &[0x83, 0xec, 0x10]), Some(0xff0)); // sub esp, 0x10
    assert_eq!(floor(64, &[0x48, 0x83, 0xe4, 0xf0]), None); // and rsp, -16
    assert_eq!(floor(64, &[0x48, 0x89, 0xdc]), None); // mov rsp, rbx
    assert_eq!(floor(64, &[0xc9]), None); // leave
    assert_eq!(floor(64, &[0x48, 0xcf]), None); // iretq
    assert_eq!(floor(64, &[0x0f, 0x05]), None); // syscall
}

/// A step's run-to (`gu`, `p` over a call) stops only for its own frame: the
/// same return site reached by a deeper call (a lower stack pointer) runs
/// on, and the return to the stepping frame stops.
#[test]
fn a_step_run_to_runs_past_a_deeper_call_of_the_same_code() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session.current_thread = "p01.01".into();
    let frame = StepFrame {
        thread: ThreadScope {
            ethread: VirtAddr(0xffff_8000_0000_1000),
            tid: Some(4),
        },
        min_stack_pointer: Some(0x2000),
    };
    session
        .add_temporary_code(VirtAddr(0x1000), Some(frame))
        .unwrap();
    let hit_with_stack = |session: &mut Session, rsp| {
        let mut regs = session.backend.read_registers().unwrap();
        for (name, value) in [("rip", 0x1000), ("rsp", rsp)] {
            session
                .register_map
                .write_u64(name, &mut regs, value)
                .unwrap();
        }
        session.backend.write_registers(&regs).unwrap();
        session.resolve_breakpoint_stop(0x1000, 0).unwrap()
    };
    assert!(matches!(
        hit_with_stack(&mut session, 0x1ff8),
        BreakpointStopAction::Resumed
    ));
    assert!(matches!(
        hit_with_stack(&mut session, 0x2000),
        BreakpointStopAction::Hit { .. }
    ));
}

/// An execution interrupted on a breakpoint's site that gets back onto it by
/// stepping, not by hitting it, runs past it on the next resume; a later
/// hit from the same stack is a new one, not that execution returning.
#[test]
fn an_interrupted_hit_stepped_back_onto_is_forgotten() {
    let mut memory = [0x90u8; 0x100];
    memory[..3].copy_from_slice(&[0x48, 0x89, 0xd8]);
    let rsp = 0x1088;
    for (index, value) in [0x1000, 0x10, 0x202, rsp, 0x18].into_iter().enumerate() {
        let at = 0x80 - 40 + index * 8;
        memory[at..at + 8].copy_from_slice(&u64::to_le_bytes(value));
    }
    let mut backend = MockBackend {
        allow_breakpoints: true,
        single_step_unsafe: true,
        halts_only_on_interrupt: true,
        landings: VecDeque::from([0x1030]),
        lands_at: Some(0x1003),
        released_to: Some(0x1030),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    backend.set("rsp", rsp);
    let mut session = stepping_session(&memory, backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session.current_thread = "p01.01".into();

    session.resume().unwrap();
    session.backend.interrupt().unwrap();
    let on_site = |session: &mut Session| {
        let backend = session.backend.as_mut();
        let mut regs = backend.read_registers().unwrap();
        let map = &session.register_map;
        map.write_u64("rip", &mut regs, 0x1000).unwrap();
        map.write_u64("rsp", &mut regs, rsp).unwrap();
        backend.write_registers(&regs).unwrap();
    };
    // Stepped back onto the site, it is stepped past it.
    on_site(&mut session);
    assert_eq!(step_rip(&mut session), 0x1003);
    on_site(&mut session);
    assert!(matches!(
        session.resolve_breakpoint_stop(0x1000, 0).unwrap(),
        BreakpointStopAction::Hit { .. }
    ));
}

/// Secure-kernel code is never patched: a step there marks its successors
/// with debug-register sites in slots no breakpoint holds.
#[test]
fn a_secure_kernel_step_uses_free_debug_register_slots_and_writes_no_code() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        single_step_unsafe: true,
        lands_at: Some(0x1002),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let mut session = stepping_session(&code, backend);
    session.target.symbols.inject_source_lines_for_test(
        2,
        0x2000,
        VirtAddr(0x1000),
        0x100,
        "secure.c",
        &[],
    );
    session.target.symbols.set_secure_roots(0x2000, []);
    // A user's `ba e1` holds slot 0.
    session.breakpoints.edit().insert_for_test(
        7,
        VirtAddr(0x1030),
        true,
        Some(HardwareBreakpoint {
            access: HwBreakpointAccess::Execute,
            len: 1,
            slot: 0,
        }),
    );

    assert_eq!(step_rip(&mut session), 0x1002);
    assert!(
        sites.lock().is_empty(),
        "a software site was planted in VTL1"
    );
    assert_eq!(
        hardware.lock()[..4],
        [(1, Some(0x1002)), (2, Some(0x1012)), (1, None), (2, None)]
    );
}

/// A backend without user-mode breakpoints (a GDB stub) cannot be trusted to
/// lift an `int3` in user space, so a step there marks its successors with
/// debug-register sites; one that has them plants software sites.
#[test]
fn a_user_space_step_uses_debug_register_sites_where_int3_is_unsafe() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    for user_mode in [false, true] {
        let mut backend = MockBackend {
            single_step_unsafe: true,
            lands_at: Some(0x1002),
            one_vcpu: true,
            allow_breakpoints: user_mode,
            ..MockBackend::default()
        };
        backend.set("rip", 0x1000);
        let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
        let mut session = stepping_session(&code, backend);

        assert_eq!(step_rip(&mut session), 0x1002);
        if user_mode {
            assert!(hardware.lock().is_empty());
            assert_eq!(sorted(&sites.lock()[..2]), [(0x1002, true), (0x1012, true)]);
        } else {
            assert!(sites.lock().is_empty(), "an int3 was planted in user space");
            let hardware = hardware.lock();
            let ((first, a), (second, b)) = (hardware[0], hardware[1]);
            assert_ne!(first, second, "{hardware:?}");
            assert_eq!(sorted(&[a, b]), [Some(0x1002), Some(0x1012)]);
        }
    }
}

/// Refusing the optional instruction marker leaves the last physical slot
/// on the successor while the other vCPUs run to free this one.
#[test]
fn a_user_space_step_completes_when_the_release_marker_is_refused() {
    let mut backend = MockBackend {
        single_step_unsafe: true,
        hardware_limit: Some(4),
        halts_only_on_interrupt: true,
        landings: VecDeque::from([0x1000]),
        released_to: Some(0x1001),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let continues = Arc::clone(&backend.continues);
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    session.current_thread = "p01.01".into();
    for slot in 0..3 {
        session.breakpoints.edit().insert_for_test(
            slot as u32,
            VirtAddr(0x1020 + slot as u64),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot,
            }),
        );
    }

    assert_eq!(step_rip(&mut session), 0x1001);
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(session.take_notices().is_empty());
    assert!(sites.lock().is_empty(), "an int3 was planted in user space");
    assert_eq!(*hardware.lock(), [(3, Some(0x1001)), (3, None)]);
    assert_eq!(session.list_breakpoints().len(), 3);
}

/// Every successor is required: refusing the second must lift the first
/// without falling back to patching user code.
#[test]
fn a_user_space_step_cleans_up_when_a_successor_is_refused() {
    let mut code = [0x90u8; 0x40];
    code[..2].copy_from_slice(&[0x74, 0x10]); // je +0x10
    let mut backend = MockBackend {
        single_step_unsafe: true,
        hardware_limit: Some(1),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let mut session = stepping_session(&code, backend);

    let error = session.step().unwrap_err();
    assert!(
        matches!(
            error,
            Error::HardwareBreakpointRefused {
                address: 0x1012,
                ref response,
            } if response == "E22"
        ),
        "{error:?}"
    );
    assert!(sites.lock().is_empty(), "an int3 was planted in user space");
    assert_eq!(*hardware.lock(), [(0, Some(0x1002)), (0, None)]);
}

/// Temporary debug-register sites retain the full logical slot ID, even
/// after hundreds of user hardware breakpoints have occupied earlier slots.
#[test]
fn a_user_space_step_uses_and_clears_a_hardware_slot_above_255() {
    let mut backend = MockBackend {
        single_step_unsafe: true,
        hardware_limit: Some(512),
        lands_at: Some(0x1001),
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1000);
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let mut session = stepping_session(&[0x90u8; 0x40], backend);
    for slot in 0..300 {
        session.breakpoints.edit().insert_for_test(
            slot as u32,
            VirtAddr(0x2000 + slot as u64),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot,
            }),
        );
    }

    assert_eq!(step_rip(&mut session), 0x1001);
    assert!(sites.lock().is_empty(), "an int3 was planted in user space");
    assert_eq!(*hardware.lock(), [(300, Some(0x1001)), (300, None)]);
    assert_eq!(session.list_breakpoints().len(), 300);
}

#[test]
fn refresh_rewrites_only_the_sites_the_stop_dropped() {
    let session = session_over_memory(0x1000, &[0u8; 0x80]);
    let mut backend = MockBackend::default().target_managed_sites();
    backend.allow_breakpoints = true;
    backend.dropped_sites = vec![0x1008];
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    manager.insert_for_test(2, VirtAddr(0x1008), true, None);
    manager.insert_for_test(3, VirtAddr(0x2000), true, None);

    manager
        .refresh_enabled(&mut backend, &session.target)
        .unwrap();

    assert_eq!(
        *backend.site_writes.lock(),
        [(0x1008, false), (0x1008, true)]
    );
}

fn manager_with_hw(slot: usize, access: HwBreakpointAccess, enabled: bool) -> BreakpointManager {
    let mut manager = BreakpointManager::new();
    let len = match access {
        HwBreakpointAccess::Execute => 1,
        _ => 4,
    };
    manager.insert_for_test(
        7,
        VirtAddr(0x1000),
        enabled,
        Some(HardwareBreakpoint { access, len, slot }),
    );
    manager
}

#[test]
fn backend_default_rejects_not_handled_continuation() {
    let mut backend = MockBackend::default();
    assert!(matches!(
        backend.continue_execution_with_disposition(ContinueDisposition::NotHandled),
        Err(Error::ExceptionDispositionUnsupported)
    ));
}

#[test]
fn exiting_takes_the_bugcheck_trap_back_out_of_the_guest() {
    // The trap is not one of the manager's breakpoints, so it is the only
    // reason to halt here, and the only site left to restore. A guest that
    // keeps it executes an int3 at nt!KeBugCheckEx with nothing attached.
    // No stop is pending, so the exit breaks in.
    let mut backend = MockBackend::default().running().halts_only_on_interrupt();
    backend.allow_breakpoints = true;
    backend.queue_interrupt(breakpoint_event(0x2000));
    let sites = Arc::clone(&backend.site_writes);
    let interrupts = Arc::clone(&backend.interrupts);
    let mut session = session_with_mock(backend);
    *session.bugcheck_trap.edit() = Some(TrapSite {
        address: VirtAddr(0x1_4000),
        original: vec![0x48],
    });

    session.cleanup_for_exit().unwrap();

    assert_eq!(*sites.lock(), [(0x1_4000, false)]);
    assert_eq!(interrupts.load(Ordering::Relaxed), 1);
    assert!(!session.has_installed_sites());
}

/// Resuming from a bugcheck stop on a backend that needs the trap steps
/// the thread past it first: resumed on it, a stub reports the trap again
/// at once, and Windows never gets to write its dump and reboot.
#[test]
fn resuming_from_the_bugcheck_trap_steps_past_it() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1_4000);
    let sites = Arc::clone(&backend.site_writes);
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    session.current_thread = "p01.01".into();
    *session.bugcheck_trap.edit() = Some(TrapSite {
        address: VirtAddr(0x1_4000),
        original: vec![0x48],
    });

    session.resume().unwrap();

    assert_eq!(*sites.lock(), [(0x1_4000, false), (0x1_4000, true)]);
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(session.bugcheck_trap.is_some());
}

/// A thread interrupted on the bugcheck trap while run past it comes back
/// to it: that hit is the bugcheck already reported, so it is stepped past
/// and resumed, not reported again. Another thread's hit is a new bugcheck.
#[test]
fn a_thread_back_on_the_bugcheck_trap_after_an_interrupt_is_resumed() {
    for (marked_stack, reported) in [(0x9000, false), (0x8000, true)] {
        let mut backend = MockBackend {
            allow_breakpoints: true,
            one_vcpu: true,
            ..MockBackend::default()
        };
        backend.set("rip", 0x1_4000);
        backend.set("rsp", 0x9000);
        let continues = Arc::clone(&backend.continues);
        let mut session = session_with_mock(backend);
        session.current_thread = "p01.01".into();
        *session.bugcheck_trap.edit() = Some(TrapSite {
            address: VirtAddr(0x1_4000),
            original: vec![0x48],
        });
        session.trap_interrupted = Some((InterruptedTrap::Bugcheck, marked_stack));

        let resolution = session
            .classify_stop_event(breakpoint_event(0x1_4000))
            .unwrap();

        assert_eq!(
            matches!(resolution, StopResolution::Bugcheck { .. }),
            reported,
            "{resolution:?}"
        );
        assert_eq!(continues.load(Ordering::Relaxed), usize::from(!reported));
    }
}

/// A session that exits while a partition view is shown cleans up the
/// target: its trap comes out through the target's backend, not the view's,
/// which refuses breakpoints, and the view is gone.
#[test]
fn exiting_from_a_partition_view_takes_the_targets_trap_out() {
    let backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    };
    let sites = Arc::clone(&backend.site_writes);
    let mut session = session_with_mock(backend);
    *session.bugcheck_trap.edit() = Some(TrapSite {
        address: VirtAddr(0x1_4000),
        original: vec![0x48],
    });
    show_partition_4(&mut session);

    session.cleanup_for_exit().unwrap();

    assert_eq!(*sites.lock(), [(0x1_4000, false)]);
    assert_eq!(session.partition(), None);
}

/// Show a view of partition 4, with one VP, over `session`'s target.
fn show_partition_4(session: &mut Session) {
    let partition_target = session_over_memory(0x1000, &[0; 0x100]).target;
    let vps = vec![PartitionVp {
        id: "p4.1".to_string(),
        registers: vec![0; REGISTER_BUFFER_SIZE],
        vcpu: None,
    }];
    session.show_partition(4, partition_target, vps, "p4.1".to_string());
}

/// A run or step in a partition view runs the target, so it is admitted on
/// the target's execution control, not refused for the view's backend,
/// which runs nothing; over a crash dump, which has none, it still is.
#[test]
fn a_partition_view_admits_runs_on_the_targets_execution_control() {
    use super::effects::{Effects, Refusal, RunEffect};
    let run = Effects {
        run: RunEffect::Run,
        ..Effects::HALTED
    };
    let step = Effects {
        run: RunEffect::Step,
        ..Effects::HALTED
    };
    let mut live = session_with_mock(MockBackend::default());
    show_partition_4(&mut live);
    let mut dump = session_over_memory(0x1000, &[0; 0x100]);
    show_partition_4(&mut dump);

    assert!(live.admit(&run).is_ok());
    assert!(live.admit(&step).is_ok());
    assert!(matches!(
        dump.admit(&run),
        Err(Refusal::NoExecutionControl { backend: "dmp" })
    ));
}

/// Every breakpoint is the target's, also in a partition view: one set there
/// is the partition's, on VP 0 when `/c 0` names it, and programmed into the
/// target's debug registers; a software one is refused, as it would be
/// planted through the target's page tables; and the target's own, set
/// before, is listed and cleared there through the target's backend.
#[test]
fn a_partition_views_breakpoints_are_the_targets() {
    let backend = MockBackend {
        host_debug_registers: true,
        allow_breakpoints: true,
        ..MockBackend::default()
    };
    let (sites, hardware) = (backend.site_writes.clone(), backend.hardware_writes.clone());
    let mut session = session_with_mock(backend);
    let execute = |session: &mut Session, address, config| {
        session.add_hardware_breakpoint(
            VirtAddr(address),
            HwBreakpointAccess::Execute,
            1,
            None,
            config,
        )
    };
    let targets = execute(
        &mut session,
        0xfffff805_d0930f10,
        BreakpointConfig::default(),
    )
    .unwrap();
    show_partition_4(&mut session);

    let partitions = execute(
        &mut session,
        0xfffff805_86ac0f10,
        BreakpointConfig {
            processor: Some(0),
            ..BreakpointConfig::default()
        },
    )
    .unwrap();
    let refused = session.add_breakpoint(VirtAddr(0x1010), None, BreakpointConfig::default());

    let partition_of = |session: &Session, id| session.breakpoint(id).unwrap().partition;
    assert_eq!(partition_of(&session, targets), None);
    assert_eq!(
        partition_of(&session, partitions),
        Some(PartitionFilter {
            partition: 4,
            vp: Some(0),
        })
    );
    assert_eq!(session.breakpoint(partitions).unwrap().processor, None);
    assert!(refused.is_err());
    assert_eq!(session.list_breakpoints().len(), 2);
    session.remove_breakpoint(targets).unwrap();
    session.remove_breakpoint(partitions).unwrap();
    assert_eq!(
        *hardware.lock(),
        [
            (0, Some(0xfffff805_d0930f10)),
            (1, Some(0xfffff805_86ac0f10)),
            (0, None),
            (1, None),
        ]
    );
    assert!(sites.lock().is_empty());
    assert_eq!(session.partition(), Some(4));
}

/// A partition view shows the partition as the target halted, and what a
/// resume runs is the target: the view is left, and the target resumed.
#[test]
fn a_resume_from_a_partition_view_runs_the_target() {
    let backend = MockBackend::default();
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    show_partition_4(&mut session);

    session.resume().unwrap();

    assert_eq!(session.partition(), None);
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// A register write to a VP in a partition view goes to the target's vCPU
/// that runs it, and only the register written: the vCPU keeps those the
/// view's copy lacks. A VP no vCPU runs is refused, its registers being the
/// hypervisor's record of them.
#[test]
fn a_vps_register_write_goes_to_the_vcpu_that_runs_it() {
    let mut backend = MockBackend::default().one_vcpu();
    backend.set("rbx", 0x1111);
    let mut session = session_with_mock(backend);
    let file = |session: &Session, rax| {
        let mut registers = vec![0; REGISTER_BUFFER_SIZE];
        session
            .register_map
            .write_u64("rax", &mut registers, rax)
            .unwrap();
        registers
    };
    let vps = vec![
        PartitionVp {
            id: "p4.1".to_string(),
            registers: file(&session, 1),
            vcpu: Some("p01.01".to_string()),
        },
        PartitionVp {
            id: "p4.2".to_string(),
            registers: file(&session, 2),
            vcpu: None,
        },
    ];
    let partition_target = session_over_memory(0x1000, &[0; 0x100]).target;
    session.show_partition(4, partition_target, vps, "p4.1".to_string());

    session.write_register("rax", 0x42).unwrap();
    let shown = session.read_registers().unwrap();
    session.set_current_thread("p4.2").unwrap();
    let refused = session.write_register("rax", 5);
    session.leave_partition();
    let vcpu = session.read_registers().unwrap();

    let read = |registers: &[u8], name| session.register_map.read_u64(name, registers).unwrap();
    assert_eq!(read(&shown, "rax"), 0x42);
    assert!(refused.is_err());
    assert_eq!((read(&vcpu, "rax"), read(&vcpu, "rbx")), (0x42, 0x1111));
}

/// A step in a partition view runs the target to a debug register of the
/// partition's on the stepping thread's next instruction. A hit there lower
/// on the stack than the step can leave it, an interrupt handler running the
/// same code, is resumed.
#[test]
fn a_partition_steps_site_takes_no_hit_deeper_on_the_stack() {
    const SITE: u64 = 0xfffff805_86ac0f15;
    let mut backend = MockBackend {
        host_debug_registers: true,
        ..MockBackend::default()
    };
    backend.set("dr6", 1);
    backend.set("rip", SITE);
    backend.set("rsp", 0x7ff8);
    let (hardware, continues) = (
        backend.hardware_writes.clone(),
        Arc::clone(&backend.continues),
    );
    let mut session = session_with_mock(backend);
    show_partition_4(&mut session);
    let frame = StepFrame {
        thread: ThreadScope {
            ethread: VirtAddr(0xffff_8000_0000_1000),
            tid: Some(4),
        },
        min_stack_pointer: Some(0x8000),
    };

    let id = session
        .add_temporary_code(VirtAddr(SITE), Some(frame))
        .unwrap();
    let site = session.breakpoint(id).unwrap();
    assert_eq!(
        site.partition,
        Some(PartitionFilter {
            partition: 4,
            vp: None,
        })
    );
    assert!(site.temporary);
    assert_eq!(*hardware.lock(), [(0, Some(SITE))]);
    // The run that takes the hit leaves the view.
    session.leave_partition();
    let resolution = session.classify_stop_event(single_step_event()).unwrap();

    assert!(
        matches!(resolution, StopResolution::Resumed),
        "{resolution:?}"
    );
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// Where the mock's `nt!DbgLoadImageSymbols` trap sits.
const LOAD_TRAP: u64 = 0x1080;
/// Where the mock's `nt!DbgUnLoadImageSymbolsUnicode` trap sits.
const UNLOAD_TRAP: u64 = 0x10c0;

/// A module trap for `event` at `address`.
fn module_trap(event: ModuleEvent, address: u64) -> ModuleTrap {
    ModuleTrap {
        event,
        site: TrapSite {
            address: VirtAddr(address),
            original: vec![0x48],
        },
        user: false,
    }
}

/// Whether `session` holds a trap for `event`.
fn has_module_trap(session: &Session, event: ModuleEvent) -> bool {
    session.module_traps.iter().any(|trap| trap.event == event)
}

/// A session over a stub (no module events) halted on its trap for `event`
/// as the kernel reports `driver.sys` at 0x2000 loading or unloading, with a
/// deferred `driver!DeferredFn` breakpoint whose symbols are available.
/// Returns it with the stub's site writes and continue count.
fn session_at_module_trap(event: ModuleEvent) -> (Session, u32, SiteWrites, Arc<AtomicUsize>) {
    let address = match event {
        ModuleEvent::Load => LOAD_TRAP,
        ModuleEvent::Unload => UNLOAD_TRAP,
    };
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    }
    .one_vcpu();
    backend.set("rip", address);
    backend.set("rdx", 0x2000);
    let sites = Arc::clone(&backend.site_writes);
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    *session.module_traps.edit() = vec![module_trap(event, address)];
    session
        .target
        .set_kernel_modules_for_test(vec![ModuleInfo::new(
            "driver.sys".into(),
            VirtAddr(0x2000),
            0x100,
        )]);
    let id = deferred_symbol_breakpoint(&mut session);
    publish_driver_symbols(&session);
    (session, id, sites, continues)
}

/// Without a break filter for the image (none, one for another module, or
/// `sxi ld:driver` over `sxe ld`), a load-trap hit is a module change: the
/// deferred breakpoint arms, the thread is stepped past the trap, and the
/// target resumes without a stop. The trap is planted again only while a
/// filter still waits on loads; with none, the breakpoint that waited was
/// the last reason for it.
#[test]
fn a_load_trap_hit_no_filter_names_arms_deferred_breakpoints_and_resumes() {
    let configurations: [&[(Option<&str>, ExceptionPolicyMode)]; 3] = [
        &[],
        &[(Some("other"), ExceptionPolicyMode::Break)],
        &[
            (None, ExceptionPolicyMode::Break),
            (Some("driver"), ExceptionPolicyMode::Ignore),
        ],
    ];
    for filters in configurations {
        let (mut session, id, sites, continues) = session_at_module_trap(ModuleEvent::Load);
        for &(module, mode) in filters {
            session.exception_policies.set_module_event(
                ModuleEvent::Load,
                module.map(str::to_string),
                mode,
                None,
            );
        }

        let resolution = session
            .classify_stop_event(breakpoint_event(LOAD_TRAP))
            .unwrap();

        assert!(matches!(resolution, StopResolution::ModulesChanged));
        assert_eq!(continues.load(Ordering::Relaxed), 1);
        let breakpoint = breakpoint_by_id(&session, id);
        assert!(breakpoint.resolved);
        assert_eq!(breakpoint.address, VirtAddr(0x1010));
        let writes = sites.lock().clone();
        let lifted = writes
            .iter()
            .position(|&write| write == (LOAD_TRAP, false))
            .expect("the trap is lifted to step past it");
        let last = writes[lifted..]
            .iter()
            .rev()
            .find(|write| write.0 == LOAD_TRAP)
            .copied();
        assert_eq!(last, Some((LOAD_TRAP, !filters.is_empty())), "{filters:?}");
        assert_eq!(
            has_module_trap(&session, ModuleEvent::Load),
            !filters.is_empty()
        );
    }
}

/// A resume keeps the load trap only while something waits on a load (an
/// `sxn`/`sxe ld` filter or an unresolved breakpoint), and the unload trap
/// only while an `sxn`/`sxe ud` filter waits on an unload. A trap nothing
/// waits on is lifted before the guest runs.
#[test]
fn a_resume_keeps_a_module_trap_only_while_its_event_is_awaited() {
    let resumed = |event: ModuleEvent, filter: Option<ExceptionPolicyMode>, deferred: bool| {
        let address = match event {
            ModuleEvent::Load => LOAD_TRAP,
            ModuleEvent::Unload => UNLOAD_TRAP,
        };
        let mut backend = MockBackend {
            allow_breakpoints: true,
            ..MockBackend::default()
        }
        .one_vcpu();
        backend.set("rip", 0x1000);
        let sites = Arc::clone(&backend.site_writes);
        let mut session = session_with_mock(backend);
        *session.module_traps.edit() = vec![module_trap(event, address)];
        if let Some(mode) = filter {
            session
                .exception_policies
                .set_module_event(event, None, mode, None);
        }
        if deferred {
            deferred_symbol_breakpoint(&mut session);
        }
        session.resume().unwrap();
        let lifted = sites.lock().contains(&(address, false));
        (has_module_trap(&session, event), lifted)
    };
    for event in [ModuleEvent::Load, ModuleEvent::Unload] {
        assert_eq!(resumed(event, None, false), (false, true), "{event:?}");
        assert_eq!(
            resumed(event, Some(ExceptionPolicyMode::Ignore), false),
            (false, true),
            "{event:?}"
        );
        assert_eq!(
            resumed(event, Some(ExceptionPolicyMode::Notify), false),
            (true, false),
            "{event:?}"
        );
        assert_eq!(
            resumed(event, Some(ExceptionPolicyMode::Break), false),
            (true, false),
            "{event:?}"
        );
    }
    assert_eq!(resumed(ModuleEvent::Load, None, true), (true, false));
    // A breakpoint waiting for its module waits on a load, not an unload.
    assert_eq!(resumed(ModuleEvent::Unload, None, true), (false, true));
}

/// A thread interrupted while run past the load trap comes back to it as
/// the same load. Lifting the unload traps meanwhile, because their filter
/// went away, must not make that return count as a new load.
#[test]
fn lifting_the_unload_traps_keeps_the_load_traps_interrupted_hit() {
    let (mut session, _, _, _) = session_at_module_trap(ModuleEvent::Load);
    session
        .module_traps
        .edit()
        .push(module_trap(ModuleEvent::Unload, UNLOAD_TRAP));
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("driver".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    let regs = session.backend.read_registers().unwrap();
    let stack = session.register_map.read_u64("rsp", &regs).unwrap();
    session.trap_interrupted = Some((
        InterruptedTrap::Module {
            event: ModuleEvent::Load,
            user: false,
        },
        stack,
    ));

    session.arm_traps();
    assert!(!has_module_trap(&session, ModuleEvent::Unload));

    let resolution = session
        .classify_stop_event(breakpoint_event(LOAD_TRAP))
        .unwrap();
    assert!(
        matches!(resolution, StopResolution::ModulesChanged),
        "the returning thread was reported as a new load: {resolution:?}"
    );
}

/// The user-image trap is a load trap too; lifting it, because no user
/// image load is awaited any more, must not take the kernel load trap's
/// marker with it.
#[test]
fn lifting_the_user_image_trap_keeps_the_load_traps_interrupted_hit() {
    let (mut session, _, _, _) = session_at_module_trap(ModuleEvent::Load);
    session.module_traps.edit().push(ModuleTrap {
        user: true,
        ..module_trap(ModuleEvent::Load, UNLOAD_TRAP)
    });
    // A filter naming a driver awaits no user-mode image.
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("driver.sys".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    let regs = session.backend.read_registers().unwrap();
    let stack = session.register_map.read_u64("rsp", &regs).unwrap();
    session.trap_interrupted = Some((
        InterruptedTrap::Module {
            event: ModuleEvent::Load,
            user: false,
        },
        stack,
    ));

    session.arm_traps();
    assert!(!session.user_image_trap_planted());

    let resolution = session
        .classify_stop_event(breakpoint_event(LOAD_TRAP))
        .unwrap();
    assert!(
        matches!(resolution, StopResolution::ModulesChanged),
        "the returning thread was reported as a new load: {resolution:?}"
    );
}

/// A breakpoint the user set on the function a module trap sits on still
/// stops when no filter surfaces the module event.
#[test]
fn a_users_breakpoint_on_a_module_trap_stops_without_a_filter() {
    for (event, address) in [
        (ModuleEvent::Load, LOAD_TRAP),
        (ModuleEvent::Unload, UNLOAD_TRAP),
    ] {
        let (mut session, _, _, continues) = session_at_module_trap(event);
        session
            .breakpoints
            .edit()
            .insert_for_test(90, VirtAddr(address), true, None);

        let resolution = session
            .classify_stop_event(breakpoint_event(address))
            .unwrap();

        assert!(
            matches!(&resolution, StopResolution::Breakpoint { breakpoint, .. } if breakpoint.id == 90),
            "{event:?}: {resolution:?}"
        );
        assert_eq!(continues.load(Ordering::Relaxed), 0, "{event:?}");
    }
}

/// A `sxe ld:<module>` filter naming the image stops at the load with the
/// module listed and its deferred breakpoint armed; resuming from that stop
/// steps past the trap before continuing.
#[test]
fn a_load_trap_hit_a_break_filter_names_surfaces_the_module_load() {
    let (mut session, id, sites, continues) = session_at_module_trap(ModuleEvent::Load);
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("driver".into()),
        ExceptionPolicyMode::Break,
        None,
    );

    let resolution = session
        .classify_stop_event(breakpoint_event(LOAD_TRAP))
        .unwrap();

    let StopResolution::ModuleLoad { module, rip, .. } = resolution else {
        panic!("expected a module-load stop, got {resolution:?}");
    };
    assert_eq!(module.name, "driver.sys");
    assert_eq!(module.base_address, VirtAddr(0x2000));
    assert_eq!(rip, LOAD_TRAP);
    assert!(matches!(
        session.current_stop.as_ref(),
        Some(ContinueOutcome::ModuleLoad { .. })
    ));
    assert_eq!(continues.load(Ordering::Relaxed), 0);
    assert!(breakpoint_by_id(&session, id).resolved);
    assert!(!sites.lock().contains(&(LOAD_TRAP, false)));

    session.resume().unwrap();

    assert_eq!(continues.load(Ordering::Relaxed), 1);
    let writes = sites.lock().clone();
    let lifted = writes
        .iter()
        .position(|&write| write == (LOAD_TRAP, false))
        .expect("resuming lifts the trap to step past it");
    assert_eq!(writes[lifted + 1], (LOAD_TRAP, true));
}

/// A `sxe ud:<module>` filter naming the image stops at the unload trap with
/// the module still listed; resuming from that stop steps past the trap. A
/// load filter for the same image does not stop there.
#[test]
fn an_unload_trap_hit_a_break_filter_names_surfaces_the_module_unload() {
    let (mut session, _, sites, continues) = session_at_module_trap(ModuleEvent::Unload);
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("driver".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    session.exception_policies.set_module_event(
        ModuleEvent::Unload,
        Some("driver".into()),
        ExceptionPolicyMode::Break,
        None,
    );

    let resolution = session
        .classify_stop_event(breakpoint_event(UNLOAD_TRAP))
        .unwrap();

    let StopResolution::ModuleUnload { module, rip, .. } = resolution else {
        panic!("expected a module-unload stop, got {resolution:?}");
    };
    assert_eq!(module.name, "driver.sys");
    assert_eq!(module.base_address, VirtAddr(0x2000));
    assert_eq!(rip, UNLOAD_TRAP);
    assert!(matches!(
        session.current_stop.as_ref(),
        Some(ContinueOutcome::ModuleUnload { .. })
    ));
    assert_eq!(continues.load(Ordering::Relaxed), 0);

    session.resume().unwrap();

    assert_eq!(continues.load(Ordering::Relaxed), 1);
    let writes = sites.lock().clone();
    let lifted = writes
        .iter()
        .position(|&write| write == (UNLOAD_TRAP, false))
        .expect("resuming lifts the trap to step past it");
    assert_eq!(writes[lifted + 1], (UNLOAD_TRAP, true));
}

/// On KD a load or unload arrives as a load-symbols notification naming the
/// image base. Each filter stops only at its own event: `sxe ld` at the load,
/// `sxe ud` at the unload, with the unloading module still listed.
#[test]
fn a_kd_module_notification_stops_only_for_its_own_filter() {
    let notification = |event| {
        let mut stop = module_change_event();
        stop.target_kernel_base_hint = Some(VirtAddr(0x2000));
        stop.module_event = Some(ModuleNotification {
            kind: event,
            base: VirtAddr(0x2000),
            size: 0,
            path: None,
            process: None,
        });
        stop
    };

    let (mut session, id, _, continues) = session_at_module_trap(ModuleEvent::Load);
    session.module_traps.edit().clear();
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        None,
        ExceptionPolicyMode::Break,
        None,
    );
    assert!(matches!(
        session
            .classify_stop_event(notification(ModuleEvent::Unload))
            .unwrap(),
        StopResolution::ModulesChanged
    ));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    let resolution = session
        .classify_stop_event(notification(ModuleEvent::Load))
        .unwrap();
    let StopResolution::ModuleLoad { module, .. } = resolution else {
        panic!("expected a module-load stop, got {resolution:?}");
    };
    assert_eq!(module.name, "driver.sys");
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert!(breakpoint_by_id(&session, id).resolved);

    let (mut session, _, _, continues) = session_at_module_trap(ModuleEvent::Unload);
    session.module_traps.edit().clear();
    session.exception_policies.set_module_event(
        ModuleEvent::Unload,
        None,
        ExceptionPolicyMode::Break,
        None,
    );
    assert!(matches!(
        session
            .classify_stop_event(notification(ModuleEvent::Load))
            .unwrap(),
        StopResolution::ModulesChanged
    ));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    let resolution = session
        .classify_stop_event(notification(ModuleEvent::Unload))
        .unwrap();
    let StopResolution::ModuleUnload { module, .. } = resolution else {
        panic!("expected a module-unload stop, got {resolution:?}");
    };
    assert_eq!(module.name, "driver.sys");
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// With `!gflag +ksl`, KD reports the user-mode images processes map. The
/// kernel module list does not hold them, so the `ld` filters match the
/// path the notification names: a filter for the DLL stops there, one for
/// another module lets the load continue.
#[test]
fn a_user_image_notification_is_filtered_by_its_path() {
    let user_load = || {
        let mut stop = module_change_event();
        stop.modules_changed = false;
        stop.module_event = Some(ModuleNotification {
            kind: ModuleEvent::Load,
            base: VirtAddr(0x7ff8_0000_0000),
            size: 0x4_0000,
            path: Some(r"\Windows\System32\MyDll.dll".to_string()),
            process: Some(0xf63e_c080),
        });
        stop
    };

    let (mut session, _, _, continues) = session_at_module_trap(ModuleEvent::Load);
    session.module_traps.edit().clear();
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("other".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    assert!(matches!(
        session.classify_stop_event(user_load()).unwrap(),
        StopResolution::ModulesChanged
    ));
    assert_eq!(continues.load(Ordering::Relaxed), 1);

    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("mydll".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    let resolution = session.classify_stop_event(user_load()).unwrap();
    let StopResolution::ModuleLoad { module, .. } = resolution else {
        panic!("expected a module-load stop, got {resolution:?}");
    };
    assert_eq!(module.name, "MyDll.dll");
    assert_eq!(module.short_name, "mydll");
    assert_eq!(module.base_address, VirtAddr(0x7ff8_0000_0000));
    assert_eq!(module.end_address(), VirtAddr(0x7ff8_0004_0000));
    assert_eq!(continues.load(Ordering::Relaxed), 1);
}

/// `sxe ld:mydll` plants the user-image trap, which on ARM64 never sees a
/// DLL loaded after its process started: Windows' own report under
/// `!gflag +ksl` is then the only one, and it stops, where it was dropped
/// for the trap to report.
#[test]
fn a_user_image_report_stops_while_the_user_image_trap_is_planted() {
    let mut stop = module_change_event();
    stop.modules_changed = false;
    stop.module_event = Some(ModuleNotification {
        kind: ModuleEvent::Load,
        base: VirtAddr(0x7ff8_0000_0000),
        size: 0x4_0000,
        path: Some(r"\ntx\MyDll.dll".to_string()),
        process: Some(0xf63e_c080),
    });
    let (mut session, _, _, continues) = session_at_module_trap(ModuleEvent::Load);
    session.module_traps.edit().clear();
    session.module_traps.edit().push(ModuleTrap {
        user: true,
        ..module_trap(ModuleEvent::Load, LOAD_TRAP)
    });
    assert!(session.user_image_trap_planted());
    session.exception_policies.set_module_event(
        ModuleEvent::Load,
        Some("mydll".into()),
        ExceptionPolicyMode::Break,
        None,
    );
    let resolution = session.classify_stop_event(stop).unwrap();
    let StopResolution::ModuleLoad { module, .. } = resolution else {
        panic!("expected a module-load stop, got {resolution:?}");
    };
    assert_eq!(module.name, "MyDll.dll");
    assert_eq!(continues.load(Ordering::Relaxed), 0);
}

/// `sxn ld` and `sxn ud` report the event as a notice and do not stop.
#[test]
fn a_module_trap_hit_a_notify_filter_names_reports_and_resumes() {
    for (event, address, line) in [
        (ModuleEvent::Load, LOAD_TRAP, "ModLoad: "),
        (
            ModuleEvent::Unload,
            UNLOAD_TRAP,
            "Unload module driver.sys at ",
        ),
    ] {
        let (mut session, _, _, continues) = session_at_module_trap(event);
        session
            .exception_policies
            .set_module_event(event, None, ExceptionPolicyMode::Notify, None);

        let resolution = session
            .classify_stop_event(breakpoint_event(address))
            .unwrap();

        assert!(matches!(resolution, StopResolution::ModulesChanged));
        assert_eq!(continues.load(Ordering::Relaxed), 1);
        let notices = session.take_notices();
        assert!(
            notices.iter().any(|notice| notice.text.starts_with(line)),
            "{event:?}: {notices:?}"
        );
    }
}

#[test]
fn successful_breakpoint_cleanup_requests_running_exit() {
    let mut backend = MockBackend::default();

    prepare_backend_after_cleanup(&mut backend, Ok(())).unwrap();

    assert_eq!(backend.exit_requests, vec![true]);
}

#[test]
fn failed_breakpoint_cleanup_requests_halted_exit() {
    let mut backend = MockBackend::default();

    let error = prepare_backend_after_cleanup(
        &mut backend,
        Err(Error::Kd("injected breakpoint removal failure".into())),
    )
    .unwrap_err();

    assert!(error.to_string().contains("breakpoint removal failure"));
    assert_eq!(backend.exit_requests, vec![false]);
}

#[test]
fn cleanup_reports_breakpoint_and_backend_teardown_failures() {
    let mut backend = MockBackend {
        fail_exit: true,
        ..MockBackend::default()
    };

    let error = prepare_backend_after_cleanup(
        &mut backend,
        Err(Error::Kd("injected breakpoint removal failure".into())),
    )
    .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("breakpoint removal failure"));
    assert!(message.contains("backend teardown failure"));
    assert_eq!(backend.exit_requests, vec![false]);
}

#[test]
fn hardware_breakpoint_hit_claims_matching_dr6_bit_and_clears_status() {
    let manager = manager_with_hw(2, HwBreakpointAccess::Write, true);
    let mut backend = MockBackend::default();
    backend.set("dr6", (1 << 2) | DR6_BS);
    backend.set("eflags", EFLAGS_BASE);

    let map = Arch::Amd64.register_map();
    let hit = hardware_breakpoint_hit(
        &mut backend,
        map,
        &manager,
        &single_step_event(),
        Arch::Amd64,
    )
    .expect("register update must succeed")
    .expect("slot 2 #DB must be claimed by the registered watch");
    assert_eq!(hit.id, 7);
    assert_eq!(hit.hardware.expect("hw params").slot, 2);

    assert_eq!(backend.get("dr6"), DR6_BS);
    assert_eq!(backend.writes, 1);
    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
}

#[test]
fn an_execute_hit_whose_dr6_names_no_cause_is_the_slot_at_the_pc() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Execute, true);
    let map = Arch::Amd64.register_map();
    let hit_at = |rip: u64, eflags: u64| {
        let mut backend = MockBackend::default();
        backend.set("dr6", 0xffff_0ff0);
        backend.set("rip", rip);
        backend.set("eflags", eflags);
        let hit = hardware_breakpoint_hit(
            &mut backend,
            map,
            &manager,
            &single_step_event(),
            Arch::Amd64,
        )
        .unwrap();
        (hit.map(|bp| bp.id), backend.get("eflags") & (1 << 16) != 0)
    };

    // Claimed, and resumed past: without RF the instruction faults again.
    assert_eq!(hit_at(0x1000, EFLAGS_BASE), (Some(7), true));
    // A trap flag explains the exception: a step that landed on the site.
    assert_eq!(hit_at(0x1000, EFLAGS_BASE | 0x100), (None, false));
    // An execute breakpoint faults at its own address only.
    assert_eq!(hit_at(0x2000, EFLAGS_BASE), (None, false));
}

/// A break-in that keeps landing on hits a filter declines (a watched
/// address other threads run faster than the target polls for the
/// break-in) holds the last one as the pause: the stop is a pause, not the
/// hit's exception, and the target stays halted on the site.
#[test]
fn a_break_in_out_of_retries_holds_a_declined_hit_as_the_pause() {
    let mut backend = MockBackend::default().running();
    backend.set("dr6", 1);
    backend.set("rip", 0x1000);
    for _ in 0..8 {
        backend.queue_interrupt(single_step_event());
    }
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    *session.breakpoints.edit() = manager_with_hw(0, HwBreakpointAccess::Execute, true);
    session
        .set_breakpoint_condition(7, Some("0".into()))
        .unwrap();

    let outcome = session.halt().unwrap();

    assert!(
        matches!(
            outcome,
            ContinueOutcome::Stopped {
                exception_code: None,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(continues.load(Ordering::Relaxed), 7);
    assert!(!session.backend.is_running());
}

#[test]
fn hardware_breakpoint_hit_sets_resume_flag_only_for_execute_watches() {
    for (access, want_rf) in [
        (HwBreakpointAccess::Execute, true),
        (HwBreakpointAccess::Write, false),
        (HwBreakpointAccess::ReadWrite, false),
    ] {
        let manager = manager_with_hw(0, access, true);
        let mut backend = MockBackend::default();
        backend.set("dr6", 1);
        backend.set("eflags", EFLAGS_BASE);

        let map = Arch::Amd64.register_map();
        let hit = hardware_breakpoint_hit(
            &mut backend,
            map,
            &manager,
            &single_step_event(),
            Arch::Amd64,
        )
        .unwrap();
        assert!(hit.is_some(), "{access:?} hit must be claimed");

        let eflags = backend.get("eflags");
        assert_eq!(eflags & RF != 0, want_rf, "{access:?}: RF mismatch");
        assert_eq!(eflags & !RF, EFLAGS_BASE, "{access:?}: eflags clobbered");
        assert_eq!(backend.get("dr6"), 0, "{access:?}: B0 not cleared");
    }
}

#[test]
fn hardware_breakpoint_hit_propagates_required_register_write_failure() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Execute, true);
    let mut backend = MockBackend::default();
    backend.set("dr6", 1);
    backend.set("eflags", EFLAGS_BASE);
    backend.fail_writes = true;

    let map = Arch::Amd64.register_map();
    assert!(
        hardware_breakpoint_hit(
            &mut backend,
            map,
            &manager,
            &single_step_event(),
            Arch::Amd64
        )
        .is_err()
    );
    assert_eq!(backend.get("dr6"), 1);
    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    assert_eq!(backend.writes, 1);
}

#[test]
fn hardware_breakpoint_hit_ignores_non_single_step_stops() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Write, true);
    let mut backend = MockBackend::default();
    backend.set("dr6", 1); // would match slot 0 if the gate were open
    let before = backend.regs.clone();
    let map = Arch::Amd64.register_map();

    let mut event = single_step_event();
    event.exception_code = Some(0x8000_0003);
    assert!(
        hardware_breakpoint_hit(&mut backend, map, &manager, &event, Arch::Amd64)
            .unwrap()
            .is_none()
    );

    event.exception_code = None;
    assert!(
        hardware_breakpoint_hit(&mut backend, map, &manager, &event, Arch::Amd64)
            .unwrap()
            .is_none()
    );

    event.exception_code = Some(STATUS_SINGLE_STEP);
    event.is_bugcheck = true;
    assert!(
        hardware_breakpoint_hit(&mut backend, map, &manager, &event, Arch::Amd64)
            .unwrap()
            .is_none()
    );

    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);
}

/// A stop from a stub: no exception code, no debug registers to read, and
/// the trapping data address reported with the stop instead.
fn stub_watch_event(address: u64) -> StopEvent {
    StopEvent {
        exception_code: None,
        first_chance: None,
        watchpoint_address: Some(address),
        ..single_step_event()
    }
}

#[test]
fn a_reported_watch_address_attributes_the_watchpoint_whose_range_covers_it() {
    // The watchpoint covers 0x1000..0x1004; the stub names the byte touched.
    let manager = manager_with_hw(0, HwBreakpointAccess::Write, true);
    let mut backend = MockBackend::default().without_debug_registers();
    let map = backend.register_map.clone();

    let hit = hardware_breakpoint_hit(
        &mut backend,
        &map,
        &manager,
        &stub_watch_event(0x1002),
        Arch::Amd64,
    )
    .unwrap()
    .expect("a byte inside the watched range belongs to the watchpoint");

    assert_eq!(hit.id, 7);
    // The address settled it, so nothing had to be fetched to decide.
    assert_eq!(backend.reads, 0);
}

#[test]
fn a_reported_watch_address_past_the_watched_range_is_not_a_hit() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Write, true);
    let mut backend = MockBackend::default().without_debug_registers();
    let map = backend.register_map.clone();

    let hit = hardware_breakpoint_hit(
        &mut backend,
        &map,
        &manager,
        &stub_watch_event(0x1004),
        Arch::Amd64,
    )
    .unwrap();

    assert!(hit.is_none());
}

/// QEMU clears a vCPU's watchpoint hit only when it reports that vCPU, so
/// one that lost the race to another vCPU's stop names its data address
/// with the vCPU's next stop, whatever made it. An address no watchpoint
/// covers then says nothing, and the execute breakpoint at the PC is hit.
#[test]
fn a_watch_address_no_watchpoint_covers_leaves_the_execute_breakpoint_at_the_pc_hit() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Execute, true);
    let mut backend = MockBackend::default().without_debug_registers();
    let map = backend.register_map.clone();
    backend.set("rip", 0x1000);

    let hit = hardware_breakpoint_hit(
        &mut backend,
        &map,
        &manager,
        &stub_watch_event(0xffff_cc0c_2cc6_7204),
        Arch::Amd64,
    )
    .unwrap();

    assert_eq!(hit.map(|bp| bp.id), Some(7));
}

/// The stale address can fall in a watchpoint still armed, as a walk's watch
/// on its thread's state is: a stop at a planted site is the site's hit all
/// the same, or the walk waiting there never sees its thread pass.
#[test]
fn a_covered_watch_address_on_a_stop_at_a_planted_site_leaves_the_site_its_hit() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    }
    .without_debug_registers();
    backend.set("rip", 0x1020);
    let map = backend.register_map.clone();
    let mut session = session_with_mock(backend);
    session.register_map = map;
    *session.breakpoints.edit() = manager_with_hw(0, HwBreakpointAccess::Write, true);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1020), true, None);

    let resolution = session
        .classify_stop_event(StopEvent {
            program_counter: Some(0x1020),
            ..stub_watch_event(0x1002)
        })
        .unwrap();

    let StopResolution::Breakpoint { breakpoint, .. } = resolution else {
        panic!("expected the site's breakpoint stop, got {resolution:?}");
    };
    assert_eq!(breakpoint.id, 1);
}

/// A one-shot watchpoint's hit is a breakpoint stop that names it, as a
/// software one-shot's is: it is kept, hidden, until the next resume removes
/// it (`resume_with_disposition`), not removed before the stop could
/// describe it.
#[test]
fn a_one_shot_watchpoint_hit_is_a_breakpoint_stop() {
    let mut backend = MockBackend::default().without_debug_registers().running();
    backend.set("rip", 0x1020);
    backend.queue_interrupt(stub_watch_event(0x1002));
    let map = backend.register_map.clone();
    let mut session = session_with_mock(backend);
    session.register_map = map;
    *session.breakpoints.edit() = manager_with_hw(0, HwBreakpointAccess::Write, true);
    session.breakpoints.edit().set_one_shot(7, true).unwrap();

    let RunOutcome::Stopped(stop) = session.run(Motion::Wait, &Cancel::poll()).unwrap() else {
        panic!("no stop surfaced");
    };
    assert_eq!(stop.breakpoint().map(|hit| hit.id), Some(7), "{stop:?}");
    assert!(
        session.breakpoints.list().is_empty(),
        "a fired one-shot is listed"
    );
    assert_eq!(
        session.breakpoints.one_shot_hit_ids(),
        [7],
        "not held for the next resume"
    );
}

#[test]
fn a_stub_with_no_debug_registers_attributes_an_execute_breakpoint_by_the_stopped_pc() {
    let manager = manager_with_hw(0, HwBreakpointAccess::Execute, true);
    let mut backend = MockBackend::default().without_debug_registers();
    let map = backend.register_map.clone();
    let event = StopEvent {
        exception_code: None,
        first_chance: None,
        ..single_step_event()
    };

    backend.set("rip", 0x1000);
    let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &event, Arch::Amd64).unwrap();
    assert_eq!(hit.map(|bp| bp.id), Some(7));
    // Without RF the resume re-enters the same faulting instruction.
    assert_eq!(backend.get("eflags") & (1 << 16), 1 << 16);

    // The breakpoint fires at its own address, so a stop elsewhere is not it.
    backend.set("rip", 0x2000);
    backend.set("eflags", 0);
    let elsewhere =
        hardware_breakpoint_hit(&mut backend, &map, &manager, &event, Arch::Amd64).unwrap();
    assert!(elsewhere.is_none());
    assert_eq!(backend.get("eflags"), 0);
}

#[test]
fn hardware_breakpoint_hit_requires_an_enabled_hardware_breakpoint() {
    let map = Arch::Amd64.register_map();
    let mut backend = MockBackend::default();
    backend.set("dr6", 1);
    let before = backend.regs.clone();

    let empty = BreakpointManager::new();
    assert!(
        hardware_breakpoint_hit(&mut backend, map, &empty, &single_step_event(), Arch::Amd64)
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);

    let manager = manager_with_hw(0, HwBreakpointAccess::Write, false);
    assert!(
        hardware_breakpoint_hit(
            &mut backend,
            map,
            &manager,
            &single_step_event(),
            Arch::Amd64
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);
}

#[test]
fn hardware_breakpoint_hit_clears_stale_dr6_bits_for_unregistered_slots() {
    let manager = manager_with_hw(1, HwBreakpointAccess::Write, true);
    let mut backend = MockBackend::default();
    backend.set("dr6", (1 << 3) | DR6_BS);

    let map = Arch::Amd64.register_map();
    assert!(
        hardware_breakpoint_hit(
            &mut backend,
            map,
            &manager,
            &single_step_event(),
            Arch::Amd64
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(backend.get("dr6"), DR6_BS);
    assert_eq!(backend.writes, 1);
}

#[test]
fn clear_trap_flag_clears_tf_and_dr6_status_in_one_write() {
    let mut backend = MockBackend::default();
    backend.set("eflags", TF | EFLAGS_BASE);
    backend.set("dr6", 0b1011 | DR6_BS);

    let map = Arch::Amd64.register_map();
    clear_trap_flag(Arch::Amd64, &mut backend, map).unwrap();

    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    assert_eq!(backend.get("dr6"), DR6_BS);
    assert_eq!(backend.writes, 1);
}

#[test]
fn clear_trap_flag_trusts_a_stop_that_reports_no_residue() {
    let mut backend = MockBackend::default().reporting_trap_state(EFLAGS_BASE, DR6_BS);
    backend.set("eflags", TF | EFLAGS_BASE);
    backend.set("dr6", 0b1011 | DR6_BS);
    let map = Arch::Amd64.register_map();

    clear_trap_flag(Arch::Amd64, &mut backend, map).unwrap();

    // The registers still hold residue, so a fetch would have rewritten
    // them: proving none happened proves the report was believed.
    assert_eq!(backend.reads, 0);
    assert_eq!(backend.writes, 0);
}

#[test]
fn clear_trap_flag_still_writes_when_the_stop_reports_residue() {
    let mut backend = MockBackend::default().reporting_trap_state(TF | EFLAGS_BASE, DR6_BS);
    backend.set("eflags", TF | EFLAGS_BASE);
    backend.set("dr6", 0b1011 | DR6_BS);
    let map = Arch::Amd64.register_map();

    clear_trap_flag(Arch::Amd64, &mut backend, map).unwrap();

    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    assert_eq!(backend.get("dr6"), DR6_BS);
}

#[test]
fn clear_trap_flag_skips_the_write_when_nothing_is_set() {
    let mut backend = MockBackend::default();
    backend.set("eflags", EFLAGS_BASE);
    backend.set("dr6", DR6_BS);
    let before = backend.regs.clone();

    let map = Arch::Amd64.register_map();
    clear_trap_flag(Arch::Amd64, &mut backend, map).unwrap();

    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);
}

#[test]
fn a_processor_filter_only_matches_the_vcpu_that_reported() {
    assert!(stopped_processor_matches(Some(1), "p01.02"));
    assert!(!stopped_processor_matches(Some(1), "p01.01"));
    assert!(!stopped_processor_matches(Some(1), "p01.04"));
    // No filter takes every stop.
    assert!(stopped_processor_matches(None, "p01.04"));
    // An unresolvable id is reported rather than dropped: a filter must
    // never lose a hit silently.
    assert!(stopped_processor_matches(Some(1), ""));
}

/// Records what the driver asked its runner for, and resumes past each
/// breakpoint action when `resume` says to.
struct RecordingRunner {
    log: Arc<Mutex<Vec<String>>>,
    resume: bool,
}

impl ActionRunner for RecordingRunner {
    fn breakpoint_action(&mut self, _session: &mut Session, action: &str) -> bool {
        self.log.lock().push(format!("action {action}"));
        self.resume
    }

    fn event_command(&mut self, _session: &mut Session, command: &str) {
        self.log.lock().push(format!("command {command}"));
    }
}

/// A session whose runner records into the returned log.
fn recording(session: &mut Session, resume: bool) -> Arc<Mutex<Vec<String>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    session.action_runner = Some(Box::new(RecordingRunner {
        log: Arc::clone(&log),
        resume,
    }));
    log
}

fn exception_event(code: u32, pc: u64) -> StopEvent {
    StopEvent {
        exception_code: Some(code),
        exception_address: Some(pc),
        program_counter: Some(pc),
        ..breakpoint_event(pc)
    }
}

/// A breakpoint hit the idle servicer parked runs its action when a wait
/// surfaces it, as a hit a wait collects itself does.
#[test]
fn a_parked_breakpoint_runs_its_action_when_it_surfaces() {
    let mut backend = MockBackend::default().running().with_pending_stop();
    backend.set("rip", 0x1000);
    backend.queue_interrupt(breakpoint_event(0x1000));
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session
        .breakpoints
        .edit()
        .set_action(1, Some("log".into()))
        .unwrap();
    let log = recording(&mut session, false);

    session.service_idle();
    assert!(log.lock().is_empty(), "idle servicing ran the action");
    assert!(!session.backend.is_running(), "the stop was not parked");

    let outcome = session.run(Motion::Wait, &Cancel::poll()).unwrap();
    let RunOutcome::Stopped(stop) = outcome else {
        panic!("no stop surfaced");
    };
    assert_eq!(stop.breakpoint().map(|hit| hit.id), Some(1));
    assert_eq!(*log.lock(), ["action log"]);
}

/// A break-in that surfaces a parked hit runs the hit's action, and a
/// resume the action asks for is ignored: halt wins.
#[test]
fn a_break_runs_a_parked_hits_action_and_stays_halted() {
    let mut backend = MockBackend::default().running().with_pending_stop();
    backend.set("rip", 0x1000);
    backend.queue_interrupt(breakpoint_event(0x1000));
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session
        .breakpoints
        .edit()
        .set_action(1, Some("gc".into()))
        .unwrap();
    let log = recording(&mut session, true);
    session.service_idle();

    let RunOutcome::Stopped(stop) = session.run(Motion::Break, &Cancel::NEVER).unwrap() else {
        panic!("no stop surfaced");
    };
    assert_eq!(stop.breakpoint().map(|hit| hit.id), Some(1));
    assert_eq!(*log.lock(), ["action gc"]);
    assert_eq!(
        continues.load(Ordering::Relaxed),
        0,
        "the action's resume ran"
    );
}

/// A hit its breakpoint declines is absorbed and the target runs on; a
/// wait whose deadline passed meanwhile ends there, handing the target
/// back running, instead of waiting on as long as declined hits keep
/// coming.
#[test]
fn a_wait_ends_at_its_deadline_between_declined_hits() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    }
    .running()
    .with_pending_stop();
    backend.set("rip", 0x1001);
    for _ in 0..3 {
        backend.queue_interrupt(breakpoint_event(0x1000));
    }
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    // Every hit is passed.
    session.breakpoints.edit().set_pass_count(1, 10).unwrap();

    let outcome = session.run(Motion::Wait, &Cancel::poll()).unwrap();
    assert!(matches!(outcome, RunOutcome::Running), "{outcome:?}");
    assert_eq!(
        continues.load(Ordering::Relaxed),
        1,
        "the wait went on past its deadline"
    );
}

/// A continue or a step issued while a parked stop waits (an SDK `run()`
/// after a `run(timeout=...)` that returned `None`) surfaces that stop,
/// with its action, instead of resuming past it.
#[test]
fn a_resume_surfaces_a_parked_stop_instead_of_losing_it() {
    let continue_ = Motion::Continue {
        disposition: ContinueDisposition::Handled,
    };
    for motion in [continue_, Motion::Step] {
        let mut backend = MockBackend::default().running().with_pending_stop();
        backend.set("rip", 0x1000);
        backend.queue_interrupt(breakpoint_event(0x1000));
        let continues = Arc::clone(&backend.continues);
        let mut session = session_with_mock(backend);
        session
            .breakpoints
            .edit()
            .insert_for_test(1, VirtAddr(0x1000), true, None);
        session
            .breakpoints
            .edit()
            .set_action(1, Some("log".into()))
            .unwrap();
        let log = recording(&mut session, false);
        session.service_idle();
        assert!(!session.backend.is_running(), "the stop was not parked");

        let RunOutcome::Stopped(stop) = session.run(motion.clone(), &Cancel::poll()).unwrap()
        else {
            panic!("{motion:?}: no stop surfaced");
        };
        assert_eq!(stop.breakpoint().map(|hit| hit.id), Some(1), "{motion:?}");
        assert_eq!(*log.lock(), ["action log"], "{motion:?}");
        assert_eq!(continues.load(Ordering::Relaxed), 0, "{motion:?} resumed");
    }
}

/// An action that resumes (`gc`) passes the hit, on a direct run as from
/// the REPL: the run goes on, and with nothing else to stop it, a bounded
/// wait hands the target back running.
#[test]
fn a_direct_run_resumes_past_a_hit_whose_action_says_so() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        schedule: VecDeque::from([Landing {
            rip: 0x1000,
            rsp: 0x2000,
            ethread: 0,
        }]),
        ..MockBackend::default()
    };
    backend.set("rip", 0x1010);
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    session.current_thread = "p01.01".into();
    session
        .breakpoints
        .edit()
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session
        .breakpoints
        .edit()
        .set_action(1, Some(".echo hit; gc".into()))
        .unwrap();
    let log = recording(&mut session, true);

    let continue_ = Motion::Continue {
        disposition: ContinueDisposition::Handled,
    };
    let outcome = session
        .run(continue_, &Cancel::within(Duration::from_millis(50)))
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Running), "{outcome:?}");
    assert_eq!(
        *log.lock(),
        [".echo hit; gc"].map(|a| format!("action {a}"))
    );
    assert!(session.backend.is_running());
    assert_eq!(continues.load(Ordering::Relaxed), 2);
}

/// A `notify` policy continues past its exception on every host's wait and
/// says so as a notice; the stop after it surfaces.
#[test]
fn a_notify_policy_continues_with_a_notice() {
    const ACCESS_VIOLATION: u32 = 0xC000_0005;
    const ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
    let mut backend = MockBackend::default().running();
    backend.set("rip", 0x1020);
    backend.queue_interrupt(exception_event(ACCESS_VIOLATION, 0x1020));
    backend.queue_interrupt(exception_event(ILLEGAL_INSTRUCTION, 0x1020));
    let continues = Arc::clone(&backend.continues);
    let mut session = session_with_mock(backend);
    // `gh`: the mock acknowledges no other disposition.
    session.exception_policies.set_with_options(
        ACCESS_VIOLATION,
        ExceptionPolicyMode::Notify,
        Some("!analyze".into()),
        Some(ExceptionPolicyFinalAction::Continue(
            ContinueDisposition::Handled,
        )),
    );
    let log = recording(&mut session, false);

    let outcome = session.run(Motion::Wait, &Cancel::NEVER).unwrap();
    let RunOutcome::Stopped(stop) = outcome else {
        panic!("no stop surfaced");
    };
    assert_eq!(
        stop.exception().map(|exception| exception.code),
        Some(ILLEGAL_INSTRUCTION)
    );
    assert_eq!(continues.load(Ordering::Relaxed), 1);
    assert_eq!(*log.lock(), ["command !analyze"]);
    let notices: Vec<String> = session
        .take_notices()
        .into_iter()
        .map(|notice| notice.text)
        .collect();
    assert!(
        notices.contains(&"Exception 0xc0000005 (first chance) at 0x1020; continuing".into()),
        "{notices:?}"
    );
}

/// A run to an address whose host cancels it with `Halt` ends halted, as an
/// interrupt stop, with its temporary site lifted: never as `Running` with
/// the target secretly halted.
#[test]
fn a_cancelled_run_to_is_an_interrupt_stop() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        halts_only_on_interrupt: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1010);
    backend.queue_interrupt(breakpoint_event(0x1050));
    let sites = Arc::clone(&backend.site_writes);
    let mut session = stepping_session(&[0x90u8; 0x80], backend);
    session.current_thread = "p01.01".into();

    let cancel = Cancel::within(Duration::from_millis(50)).with_behavior(CancelBehavior::Halt);
    let run_to = Motion::RunTo {
        address: VirtAddr(0x1040),
        frame: None,
        disposition: ContinueDisposition::Handled,
    };
    let outcome = session.run(run_to, &cancel).unwrap();
    let RunOutcome::Stopped(stop) = outcome else {
        panic!("a halted run reported Running");
    };
    assert!(matches!(stop.kind, StopKind::Interrupt), "{:?}", stop.kind);
    assert!(!session.backend.is_running());
    assert_eq!(sites.lock().last(), Some(&(0x1040, false)));
    assert!(session.breakpoints.list().is_empty());
}

/// The same run handed back running (a remote client's budget) leaves its
/// site armed, for a later wait to stop at; that stop ends the run and
/// takes the site out, or it went on stopping the thread there for good.
#[test]
fn a_run_to_handed_back_running_leaves_its_site_armed() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        halts_only_on_interrupt: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1010);
    backend.queue_interrupt(breakpoint_event(0x1040));
    let sites = Arc::clone(&backend.site_writes);
    let mut session = stepping_session(&[0x90u8; 0x80], backend);
    session.current_thread = "p01.01".into();

    let run_to = Motion::RunTo {
        address: VirtAddr(0x1040),
        frame: None,
        disposition: ContinueDisposition::Handled,
    };
    let outcome = session
        .run(run_to, &Cancel::within(Duration::from_millis(20)))
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Running));
    assert_eq!(session.breakpoints.list().len(), 1);

    let RunOutcome::Stopped(_) = session
        .run(Motion::Break, &Cancel::within(Duration::from_millis(50)))
        .unwrap()
    else {
        panic!("the break-in reported Running");
    };
    assert!(session.breakpoints.list().is_empty());
    assert_eq!(sites.lock().last(), Some(&(0x1040, false)));
}

/// A run handed back running and then replaced by a new run, as a DAP
/// `continue` sent while a step still runs does, the new run ends the old:
/// its site comes out rather than ending the continue as a step.
#[test]
fn a_new_run_ends_the_run_handed_back_running() {
    let mut session = handed_back_run_to(0x1040, 1);
    let outcome = session
        .run(
            Motion::Continue {
                disposition: ContinueDisposition::Handled,
            },
            &Cancel::within(Duration::from_millis(20)),
        )
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Running));
    assert!(session.breakpoints.list().is_empty());
}

/// A breakpoint that reuses the id of a handed-back run's site, removed
/// meanwhile, is not the run's to take out when the run ends.
#[test]
fn ending_a_handed_back_run_keeps_a_breakpoint_that_reused_its_site_id() {
    let mut session = handed_back_run_to(0x1040, 2);
    let site = session.breakpoints.list()[0].id;
    let reused = session
        .with_target_halted(|session| {
            session.remove_breakpoint(site)?;
            session.add_breakpoint(VirtAddr(0x1050), None, BreakpointConfig::default())
        })
        .unwrap();
    assert_eq!(reused, site);

    session.end_handed_back_run();
    let left: Vec<u64> = session
        .breakpoints
        .list()
        .iter()
        .map(|breakpoint| breakpoint.address.0)
        .collect();
    assert_eq!(left, [0x1050]);
}

/// A session whose run to `address` was handed back running, its site
/// armed, with `breakins` break-ins queued for the edits that follow.
fn handed_back_run_to(address: u64, breakins: usize) -> Session {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        one_vcpu: true,
        halts_only_on_interrupt: true,
        ..MockBackend::default()
    };
    backend.set("rip", 0x1010);
    for _ in 0..breakins {
        backend.queue_interrupt(breakpoint_event(0x2000));
    }
    let mut session = stepping_session(&[0x90u8; 0x80], backend);
    session.current_thread = "p01.01".into();
    let run_to = Motion::RunTo {
        address: VirtAddr(address),
        frame: None,
        disposition: ContinueDisposition::Handled,
    };
    let outcome = session
        .run(run_to, &Cancel::within(Duration::from_millis(20)))
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Running));
    assert_eq!(session.breakpoints.list().len(), 1);
    session
}

/// A stop's report takes the module traps in its window out of the
/// target's table too; resuming plants them again, or their events stop.
#[test]
fn resuming_replants_the_module_traps_a_stop_dropped() {
    let mut backend = MockBackend {
        allow_breakpoints: true,
        ..MockBackend::default()
    }
    .target_managed_sites();
    backend.dropped_sites = vec![LOAD_TRAP];
    let sites = Arc::clone(&backend.site_writes);
    let mut session = session_with_mock(backend);
    *session.module_traps.edit() = vec![
        module_trap(ModuleEvent::Load, LOAD_TRAP),
        module_trap(ModuleEvent::Unload, UNLOAD_TRAP),
    ];
    for event in [ModuleEvent::Load, ModuleEvent::Unload] {
        session
            .exception_policies
            .set_module_event(event, None, ExceptionPolicyMode::Break, None);
    }

    session.arm_traps();

    assert_eq!(*sites.lock(), [(LOAD_TRAP, true)]);
}
