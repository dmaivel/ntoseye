use super::*;
use crate::gdb::breakpoints::HardwareBreakpoint;
use crate::kd::context::{REGISTER_BUFFER_SIZE, build_register_map};
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

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
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            register_map: build_register_map(),
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
        }
    }
}

impl MockBackend {
    pub fn running(mut self) -> Self {
        self.running = true;
        self
    }

    /// Model a target that owns its breakpoint table (KD), not a stub
    /// that leaves our patched byte in place across a stop.
    fn target_managed_sites(mut self) -> Self {
        self.target_manages_sites = true;
        self
    }

    pub fn queue_interrupt(&mut self, event: StopEvent) {
        self.interrupt_events.push_back(event);
    }

    fn set(&mut self, name: &str, value: u64) {
        self.register_map
            .write_u64(name, &mut self.regs, value)
            .unwrap();
    }

    fn get(&self, name: &str) -> u64 {
        self.register_map.read_u64(name, &self.regs).unwrap()
    }
}

impl DebugBackend for MockBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn read_registers(&mut self) -> Result<Vec<u8>> {
        Ok(self.regs.clone())
    }
    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.writes += 1;
        if self.fail_writes {
            return Err(Error::Kd("injected register write failure".into()));
        }
        self.regs = data.to_vec();
        Ok(())
    }
    fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
        if self.allow_breakpoints {
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        if self.allow_breakpoints {
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }
    fn target_manages_breakpoint_sites(&self) -> bool {
        self.target_manages_sites
    }
    fn continue_execution(&mut self) -> Result<()> {
        self.continues.fetch_add(1, Ordering::Relaxed);
        self.running = true;
        Ok(())
    }
    /// A step lands one byte on, reported by the queued single-step event.
    fn step(&mut self) -> Result<()> {
        let rip = self.get("rip");
        self.set("rip", rip + 1);
        self.interrupt_events.push_back(single_step_event());
        Ok(())
    }
    fn interrupt(&mut self) -> Result<StopEvent> {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        let event = self
            .interrupt_events
            .pop_front()
            .ok_or(Error::NotSupported)?;
        self.running = false;
        Ok(event)
    }
    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let event = self
            .interrupt_events
            .pop_front()
            .ok_or(Error::NotSupported)?;
        self.running = false;
        Ok(event)
    }
    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        let event = self.interrupt_events.pop_front();
        if event.is_some() {
            self.running = false;
        }
        Ok(event)
    }
    fn thread_list(&mut self) -> Result<Vec<String>> {
        Err(Error::NotSupported)
    }
    fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
        Err(Error::NotSupported)
    }
    fn stopped_thread_id(&mut self) -> Result<String> {
        Err(Error::NotSupported)
    }
    fn is_running(&self) -> bool {
        self.running
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
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        assisted_breakin: false,
    }
}

pub fn breakpoint_event(pc: u64) -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: Some(STATUS_BREAKPOINT),
        first_chance: Some(true),
        exception_address: Some(pc),
        program_counter: Some(pc),
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        assisted_breakin: false,
    }
}

fn module_change_event() -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: true,
        assisted_breakin: false,
    }
}

pub fn session_with_mock(backend: MockBackend) -> Session {
    let mut session = session_over_memory(0x1000, &[0; 0x100]);
    session.backend = Box::new(backend);
    session.register_map = build_register_map();
    session
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

#[test]
fn with_target_halted_parks_a_genuine_pending_breakpoint() {
    let mut backend = MockBackend::default().running();
    backend.set("rip", 0x1000);
    let continues = Arc::clone(&backend.continues);
    backend.queue_interrupt(breakpoint_event(0x1000));
    let mut session = session_with_mock(backend);
    session
        .breakpoints
        .insert_for_test(1, VirtAddr(0x1000), true, None);

    session.with_target_halted(|_| Ok(())).unwrap();

    assert_eq!(continues.load(Ordering::Relaxed), 0);
    assert!(!session.backend.is_running());
    let cancel = AtomicBool::new(false);
    assert!(matches!(
        session.wait_for_stop_bounded(Some(Duration::ZERO), &cancel),
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
fn a_target_owned_breakpoint_is_left_for_the_target_to_step_over() {
    let session = session_over_memory(0x1000, &[0u8; 0x80]);
    let mut backend = MockBackend::default().target_managed_sites();
    // A dance would succeed here, so only the ownership check can stop it.
    backend.allow_breakpoints = true;
    backend.set("rip", 0x1000);
    let mut manager = BreakpointManager::new();
    manager.insert_for_test(1, VirtAddr(0x1000), true, None);
    let register_map = backend.register_map().clone();

    let stepped =
        step_over_current_breakpoint(&mut backend, &register_map, &session.target, &mut manager)
            .unwrap();

    assert!(!stepped, "host stepped a site the target owns");
    assert!(
        manager.list()[0].enabled,
        "the site was disowned across the resume"
    );
    assert_eq!(backend.writes, 0, "the guest context was rewritten");
}

fn manager_with_hw(slot: u8, access: HwBreakpointAccess, enabled: bool) -> BreakpointManager {
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

    let map = build_register_map();
    let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
        .expect("register update must succeed")
        .expect("slot 2 #DB must be claimed by the registered watch");
    assert_eq!(hit.id, 7);
    assert_eq!(hit.hardware.expect("hw params").slot, 2);

    assert_eq!(backend.get("dr6"), DR6_BS);
    assert_eq!(backend.writes, 1);
    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
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

        let map = build_register_map();
        let hit =
            hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event()).unwrap();
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

    let map = build_register_map();
    assert!(hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event()).is_err());
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
    let map = build_register_map();

    let mut event = single_step_event();
    event.exception_code = Some(0x8000_0003);
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
            .unwrap()
            .is_none()
    );

    event.exception_code = None;
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
            .unwrap()
            .is_none()
    );

    event.exception_code = Some(STATUS_SINGLE_STEP);
    event.is_bugcheck = true;
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
            .unwrap()
            .is_none()
    );

    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);
}

#[test]
fn hardware_breakpoint_hit_requires_an_enabled_hardware_breakpoint() {
    let map = build_register_map();
    let mut backend = MockBackend::default();
    backend.set("dr6", 1);
    let before = backend.regs.clone();

    let empty = BreakpointManager::new();
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &empty, &single_step_event())
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);

    let manager = manager_with_hw(0, HwBreakpointAccess::Write, false);
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
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

    let map = build_register_map();
    assert!(
        hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
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

    let map = build_register_map();
    clear_trap_flag(&mut backend, &map).unwrap();

    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    assert_eq!(backend.get("dr6"), DR6_BS);
    assert_eq!(backend.writes, 1);
}

#[test]
fn clear_trap_flag_skips_the_write_when_nothing_is_set() {
    let mut backend = MockBackend::default();
    backend.set("eflags", EFLAGS_BASE);
    backend.set("dr6", DR6_BS);
    let before = backend.regs.clone();

    let map = build_register_map();
    clear_trap_flag(&mut backend, &map).unwrap();

    assert_eq!(backend.writes, 0);
    assert_eq!(backend.regs, before);
}
