use super::hits::{
    hardware_breakpoint_hit, rewind_thread_off_breakpoint, stopped_processor_matches,
};
use super::inspection::DBG_STATUS_WORKER;
use super::lifecycle::prepare_backend_after_cleanup;
use super::stepping::{site_successors, step_over_current_breakpoint};
use super::*;
use crate::breakpoints::{Breakpoint, BreakpointConfig, HardwareBreakpoint};
use crate::dbg_backend::{ContinueDisposition, HwBreakpointAccess, TrapState, clear_trap_flag};
use crate::dmp::{IMAGE_FILE_MACHINE_ARM64, structs::Header64};
use crate::kd::context::{REGISTER_BUFFER_SIZE, build_register_map};
use crate::kd::context_arm64;
use crate::memory::PAGE_SIZE;
use crate::types::{Arch, VirtAddr};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;

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
    site_writes: Arc<Mutex<Vec<(u64, bool)>>>,
    /// Register fetches, so a test can prove a path avoided one.
    reads: usize,
    /// TF and DR6 as a transport would report them with the stop.
    reported_trap_state: Option<TrapState>,
    /// Single steps are unsafe (the Windows hypervisor); `step()` then fails
    /// the test, and `continue_current_thread` lands on `lands_at`.
    single_step_unsafe: bool,
    /// Where the lone vCPU stops when resumed alone; `None` never stops.
    lands_at: Option<u64>,
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
            halts_only_on_interrupt: false,
            pending_stop: false,
            dropped_sites: Vec::new(),
            site_writes: Arc::new(Mutex::new(Vec::new())),
            reads: 0,
            reported_trap_state: None,
            single_step_unsafe: false,
            lands_at: None,
        }
    }
}

impl MockBackend {
    pub fn running(mut self) -> Self {
        self.running = true;
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
        self.register_map = RegisterMap::parse_target_xml(
            r#"<target><feature name="org.gnu.gdb.i386.core">
                 <reg name="rsp" bitsize="64"/>
                 <reg name="rip" bitsize="64"/>
                 <reg name="eflags" bitsize="32"/>
               </feature></target>"#,
        )
        .unwrap();
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
        self.reads += 1;
        Ok(self.regs.clone())
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
    fn sites_dropped_by_stop(&self) -> Vec<u64> {
        self.dropped_sites.clone()
    }
    fn continue_execution(&mut self) -> Result<()> {
        self.continues.fetch_add(1, Ordering::Relaxed);
        self.running = true;
        Ok(())
    }
    fn single_step_unsafe(&self) -> bool {
        self.single_step_unsafe
    }
    /// The lone vCPU reaches `lands_at` and reports a breakpoint there.
    fn continue_current_thread(&mut self) -> Result<()> {
        self.running = true;
        if let Some(address) = self.lands_at {
            self.set("rip", address);
            self.interrupt_events.push_back(breakpoint_event(address));
        }
        Ok(())
    }
    /// A step lands one byte on, reported by the queued single-step event.
    fn step(&mut self) -> Result<()> {
        assert!(
            !self.single_step_unsafe,
            "single-stepped where it is unsafe"
        );
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
        if self.halts_only_on_interrupt {
            return Ok(None);
        }
        let event = self.interrupt_events.pop_front();
        if event.is_some() {
            self.running = false;
            self.pending_stop = false;
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
    fn has_pending_stop(&self) -> bool {
        self.pending_stop
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
        watchpoint_address: None,
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
        watchpoint_address: None,
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

fn session_over_arm64_memory(base: u64, memory: &[u8]) -> Session {
    let block = TriageBlock {
        address: base,
        offset: 0,
        size: memory.len() as u32,
    };
    let mut dump = make_triage_dump(&[block], &[(base, memory)]);
    let machine_offset = std::mem::offset_of!(Header64, machine_image_type);
    dump[machine_offset..machine_offset + 4]
        .copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = temp_dir().join(format!("ntoseye-session-arm64-{sequence}-{}.dmp", id()));
    write(&path, dump).unwrap();
    let session = Session::open(&TargetSpec::Dump(path.clone())).unwrap();
    remove_file(path).unwrap();
    session
}

#[test]
fn page_in_result_reads_arm64_pc_alias_and_first_argument() {
    let mut session = session_over_arm64_memory(0x1000, &[0; 0x100]);
    assert_eq!(session.target.arch(), Arch::Arm64);

    let mut backend = MockBackend {
        register_map: context_arm64::build_register_map(),
        regs: vec![0; context_arm64::REGISTER_BUFFER_SIZE],
        ..MockBackend::default()
    };
    backend.set("rip", 0x2000);
    backend.set("x0", DBG_STATUS_WORKER);
    session.register_map = backend.register_map.clone();
    session.backend = Box::new(backend);

    let report = session.page_in_result(VirtAddr(0x1000), VirtAddr(0x2000));

    assert!(report.from_worker);
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
    session.read_masked(va, &mut bytes).unwrap();
    let hits = session.target.search(va, b"SE", 4).unwrap();

    assert_eq!(&bytes, b"USER");
    assert_eq!(hits, [USER_VA + 1]);
}

/// A WOW64 process's x86 code builds 32-bit string descriptors: `Buffer` is a
/// 4-byte pointer at offset 4. `.effmach x86` (or an explicit width) reads
/// them with WOW64 ntdll's layout instead of the kernel's 64-bit one.
#[test]
fn string_descriptors_follow_the_requested_width() {
    use crate::layout::{FieldInfo, ParsedType, TypeInfo};
    use crate::target::CODE_BITNESS_X86;

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
    session.target.effmach = Some(CODE_BITNESS_X86);
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
    let mut session = session_over_memory(base, &mapped);

    let read = session
        .read_terminated(VirtAddr(base + PAGE_SIZE as u64 - 1), 2, 2)
        .unwrap();
    assert_eq!(read.bytes, vec![0x41, 0x00]);
    assert!(!read.unreadable);

    let page = vec![b'X'; PAGE_SIZE];
    let mut session = session_over_memory(base, &page);
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
        .insert_for_test(1, VirtAddr(0x1000), true, None);
    session.breakpoints.set_pass_count(1, 2).unwrap();
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

#[test]
fn absorbed_watchpoint_invalidates_stopped_inspection() {
    let mut backend = MockBackend::default();
    backend.set("dr6", 1);
    backend.set("rip", 0x1010);
    let mut session = session_with_mock(backend);
    session.breakpoints = manager_with_hw(0, HwBreakpointAccess::Write, true);
    session.breakpoints.set_pass_count(7, 2).unwrap();

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

fn breakpoint_by_id(session: &Session, id: u32) -> Breakpoint {
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

    let stepped =
        step_over_current_breakpoint(&mut backend, &register_map, &session.target, &mut manager)
            .unwrap();

    assert!(stepped);
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

    let passed =
        step_over_current_breakpoint(&mut backend, &register_map, &session.target, &mut manager)
            .unwrap();

    assert!(passed);
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
        step_over_current_breakpoint(&mut backend, &register_map, &session.target, &mut manager)
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
        |rip| site_successors(&session.target, &register_map, &regs, rip, None).unwrap();

    assert_eq!(successors(0x1000), [0x1002, 0x1012]);
    assert_eq!(successors(0x1010), [0x2222]);
    assert_eq!(successors(0x1020), [0x3333]);
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
fn exiting_takes_the_bugcheck_trap_back_out_of_the_guest() {
    // The trap is not one of the manager's breakpoints, so it is the only
    // reason to halt here, and the only site left to restore. A guest that
    // keeps it executes an int3 at nt!KeBugCheckEx with nothing attached.
    let mut backend = MockBackend::default().running();
    backend.allow_breakpoints = true;
    backend.queue_interrupt(breakpoint_event(0x2000));
    let sites = Arc::clone(&backend.site_writes);
    let interrupts = Arc::clone(&backend.interrupts);
    let mut session = session_with_mock(backend);
    session.bugcheck_trap = Some(VirtAddr(0x1_4000));

    session.cleanup_for_exit().unwrap();

    assert_eq!(*sites.lock(), [(0x1_4000, false)]);
    assert_eq!(interrupts.load(Ordering::Relaxed), 1);
    assert!(!session.has_installed_sites());
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

    let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &stub_watch_event(0x1002))
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

    let hit =
        hardware_breakpoint_hit(&mut backend, &map, &manager, &stub_watch_event(0x1004)).unwrap();

    assert!(hit.is_none());
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
    let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &event).unwrap();
    assert_eq!(hit.map(|bp| bp.id), Some(7));
    // Without RF the resume re-enters the same faulting instruction.
    assert_eq!(backend.get("eflags") & (1 << 16), 1 << 16);

    // The breakpoint fires at its own address, so a stop elsewhere is not it.
    backend.set("rip", 0x2000);
    backend.set("eflags", 0);
    let elsewhere = hardware_breakpoint_hit(&mut backend, &map, &manager, &event).unwrap();
    assert!(elsewhere.is_none());
    assert_eq!(backend.get("eflags"), 0);
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
fn clear_trap_flag_trusts_a_stop_that_reports_no_residue() {
    let mut backend = MockBackend::default().reporting_trap_state(EFLAGS_BASE, DR6_BS);
    backend.set("eflags", TF | EFLAGS_BASE);
    backend.set("dr6", 0b1011 | DR6_BS);
    let map = build_register_map();

    clear_trap_flag(&mut backend, &map).unwrap();

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
    let map = build_register_map();

    clear_trap_flag(&mut backend, &map).unwrap();

    assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    assert_eq!(backend.get("dr6"), DR6_BS);
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
