//! A live user-mode target behind a DbgRpc process server: one process, its
//! threads, and its registers, with breakpoints patched into the process's
//! own code or delegated to the server.
//!
//! The server supplies the primitives (`ReadVirtual`, `GetContext`,
//! `WaitForEvent`, ...); everything above — symbols, the Windows model,
//! stacks, the REPL — shares the user-mode model with minidumps.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::arch::debug_registers::invalid_slot;
use crate::arch::{Arch, HardwareWatch, HwBreakpointAccess, RegisterMap};
use crate::backend::dbg_backend::{
    BackendCapability, ContinueDisposition, DebugBackend, DebugCapability, DebugLog,
    DebugOutputPage, ExceptionRecord, ModuleEvent, ModuleNotification, StopEvent,
};
use crate::backend::userlive::{
    LiveProcessInfo, LiveProcessState, LiveUserThread, backend_thread_id, parse_backend_thread_id,
};
use crate::base::bytes::utf16le_nul_terminated;
use crate::base::error::{Error, Result};
use crate::base::ntstatus::{DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED};
use crate::base::types::VirtAddr;

use super::client::{DbgsrvClient, DbgsrvUserMemory};
use super::events::{self, DebugEvent};
use super::service::{
    DEBUG_PROCESS_ONLY_THIS_PROCESS, E_ACCESSDENIED, E_INVALIDARG, MAX_PROCESS_THREADS,
    PROC_INFO_NO_SUSPEND,
};

/// How long one `WaitForEvent` may take, so a Ctrl+C seen between polls can
/// break the process in without a second thread.
const EVENT_POLL_MS: u32 = 100;

/// How long the attach waits for its first debug event: the server has
/// already queued the process's creation by then, so this only waits for
/// delivery.
const ATTACH_EVENT_MS: u32 = 4_000;

/// How many break-in attempts [`DebugBackend::interrupt`] waits through, each
/// [`EVENT_POLL_MS`] long, before giving up.
const BREAK_IN_TRIES: usize = 100;

/// How many threads a single `GetProcessInfo` asks for before growing the
/// request.
const THREAD_INFO_START: u32 = 64;

/// Retained debug-output lines (`OUTPUT_DEBUG_STRING_EVENT`), matching KD's
/// ring capacity.
const DEBUG_LOG_CAPACITY: usize = 4096;

/// One thread tracked by the backend: its server handle plus the public
/// metadata mirrored to [`LiveProcessState`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendThread {
    handle: u64,
    info: LiveUserThread,
}

/// What the debugger is attached to: an existing process, or one it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbgsrvTarget {
    /// `--process <pid>`: attach to a running process.
    Attach { pid: u32 },
    /// `--create <command line>`: start a process under the debugger.
    Create { command_line: String },
}

impl DbgsrvTarget {
    /// Resolve the mutually exclusive `(process, create)` options shared by
    /// the CLI, MCP, DAP, and Python SDK hosts.
    pub fn from_options(process: Option<u32>, create: Option<String>) -> Result<Self> {
        match (process, create) {
            (Some(pid), None) => Ok(Self::Attach { pid }),
            (None, Some(command_line)) => Ok(Self::Create { command_line }),
            (None, None) => Err(Error::InvalidArgument(
                "dbgsrv requires exactly one of 'process' and 'create'".to_string(),
            )),
            (Some(_), Some(_)) => Err(Error::InvalidArgument(
                "'process' and 'create' are mutually exclusive".to_string(),
            )),
        }
    }
}

pub struct DbgsrvBackend {
    client: Arc<DbgsrvClient>,
    pid: u32,
    /// The process server's handle to the process, shared with
    /// [`DbgsrvUserMemory`] so a handle update from `CreateProcess` stays in
    /// sync.
    process: Arc<AtomicU64>,
    arch: Arch,
    register_map: RegisterMap,
    /// Shared live metadata (PEB, image base/hint, threads) read by `Target`.
    live_state: LiveProcessState,
    threads: Vec<BackendThread>,
    current: usize,
    /// The stop the target is held at, when it is not running.
    stop: Option<StopEvent>,
    /// The exception record of the last exception stop, for `.exr -1`.
    last_exception: Option<ExceptionRecord>,
    running: bool,
    /// The process's exit status, once it reported one.
    exit: Option<u32>,
    /// Sites this debugger patched into the process, and the instructions
    /// they displaced, when the server has no breakpoint implementation.
    patched: HashMap<u64, Vec<u8>>,
    /// Sites the server planted, with the storage it filled.
    service_plants: HashMap<u64, Vec<u8>>,
    debug_log: DebugLog,
    /// A module load or unload the backend saw, not yet taken by the session.
    modules_changed: bool,
    /// Raised by the host (Ctrl+C) and by [`Self::interrupt`]'s caller: the
    /// stop wait breaks the process in when it sees it.
    interrupt: Arc<AtomicBool>,
    /// The thread whose single-step flag is armed by a step that has not
    /// stopped yet.
    armed_step: Option<u64>,
    /// The watchpoints armed in this process's threads, by slot: debug
    /// registers are per thread, so threads created later are armed from here.
    hardware: BTreeMap<usize, HardwareWatch>,
}

impl DbgsrvBackend {
    /// Attach to, or create, the process `target` names, and hold it at its
    /// first debug event.
    pub fn connect(
        client: Arc<DbgsrvClient>,
        target: &DbgsrvTarget,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        let arch = client.arch();
        let (pid, process_handle, image_hint) = match target {
            DbgsrvTarget::Attach { pid } => {
                // Attach first: enumerating the machine's processes is a
                // separate privilege, and the attach itself says whether the
                // process is there.
                progress(&format!("dbgsrv: attaching to process {pid}"));
                let attached =
                    client
                        .server()
                        .attach_process(*pid, 0)
                        .map_err(|error| match error {
                            Error::DbgsrvStatus {
                                status: E_INVALIDARG,
                                ..
                            } => Error::Dbgsrv(format!(
                                "process {pid} not found (HRESULT {E_INVALIDARG:#010x})"
                            )),
                            Error::DbgsrvStatus {
                                status: E_ACCESSDENIED,
                                ..
                            } => Error::Dbgsrv(format!(
                                "access denied attaching to process {pid} (HRESULT {E_ACCESSDENIED:#010x})"
                            )),
                            other => other,
                        })?;
                (*pid, attached.handle, None)
            }
            DbgsrvTarget::Create { command_line } => {
                progress(&format!("dbgsrv: creating '{command_line}'"));
                let hint = command_line
                    .rsplit(['\\', '/'])
                    .next()
                    .filter(|name| !name.is_empty())
                    .map(str::to_string);
                let created = client.server().create_process(
                    command_line,
                    DEBUG_PROCESS_ONLY_THIS_PROCESS,
                    false,
                    None,
                )?;
                progress(&format!(
                    "dbgsrv: created process {} (thread {:#x})",
                    created.pid, created.tid
                ));
                (created.pid, created.process_handle, hint)
            }
        };
        let peb = client
            .server()
            .process_data_offset(process_handle)
            .ok()
            .filter(|peb| *peb != 0);
        progress(&format!(
            "dbgsrv: process {pid} attached (handle {process_handle:#x}, PEB {:#x})",
            peb.unwrap_or(0)
        ));
        let live_state = LiveProcessState::new(LiveProcessInfo {
            pid,
            peb,
            image_base: None,
            image_hint,
            threads: Vec::new(),
        });
        let mut backend = Self {
            client: Arc::clone(&client),
            pid,
            process: Arc::new(AtomicU64::new(process_handle)),
            arch,
            register_map: arch.register_map().clone(),
            live_state,
            threads: Vec::new(),
            current: 0,
            stop: None,
            last_exception: None,
            running: false,
            exit: None,
            patched: HashMap::new(),
            service_plants: HashMap::new(),
            debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
            modules_changed: false,
            interrupt: Arc::new(AtomicBool::new(false)),
            armed_step: None,
            hardware: BTreeMap::new(),
        };
        backend.reload_threads()?;
        progress(&format!("dbgsrv: {} thread(s)", backend.threads.len()));
        if backend.threads.is_empty() {
            progress(&format!(
                "dbgsrv: process {pid} lists no threads; select one with ~<n>s once it has one"
            ));
        }
        // The process's creation is already queued: it is the stop the target
        // sits at until a run command.
        let stop = backend
            .next_stop(ATTACH_EVENT_MS)?
            .ok_or_else(|| Error::Dbgsrv("attach produced no initial debug event".to_string()))?;
        backend.stop = Some(stop);
        backend.running = false;
        Ok(backend)
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The process server's handle to the process.
    pub fn process_handle(&self) -> u64 {
        self.process.load(Ordering::Acquire)
    }

    /// The virtual-memory adapter bound to this process.
    pub fn user_memory(&self) -> Arc<DbgsrvUserMemory> {
        Arc::new(DbgsrvUserMemory::new(
            Arc::clone(&self.client),
            Arc::clone(&self.process),
        ))
    }

    /// The shared live process metadata read by `Target`.
    pub fn live_state(&self) -> LiveProcessState {
        self.live_state.clone()
    }

    /// The thread id selected at open time, if any.
    pub fn selected_tid(&self) -> Option<u32> {
        self.threads.get(self.current).map(|thread| thread.info.tid)
    }

    /// The flag a host raises to interrupt work on this target: the stop wait
    /// breaks the process in when it sees it, and Ctrl+C raises it.
    pub fn interrupt_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupt)
    }

    pub fn client(&self) -> &Arc<DbgsrvClient> {
        &self.client
    }

    fn require_alive(&self) -> Result<()> {
        match self.exit {
            Some(code) => Err(Error::Dbgsrv(format!("process exited: {code}"))),
            None => Ok(()),
        }
    }

    fn current_thread(&self) -> Result<&BackendThread> {
        self.threads
            .get(self.current)
            .ok_or_else(|| Error::Dbgsrv(format!("process {} has no thread to inspect", self.pid)))
    }

    fn sync_live_threads(&self) {
        self.live_state.update(|info| {
            info.threads = self
                .threads
                .iter()
                .map(|thread| thread.info.clone())
                .collect();
        });
    }

    /// Ask the server for the process's threads and their TEBs, growing the
    /// request once if it listed more than fit.
    fn reload_threads(&mut self) -> Result<()> {
        let mut wanted = THREAD_INFO_START;
        let records = loop {
            let (_, mut records, total) =
                self.client
                    .server()
                    .process_info(self.pid, PROC_INFO_NO_SUSPEND, wanted)?;
            if total <= wanted || wanted >= MAX_PROCESS_THREADS {
                records.truncate(wanted as usize);
                break records;
            }
            // Clamp to avoid trusting a corrupt count from the server.
            wanted = total.min(MAX_PROCESS_THREADS);
        };
        let process = self.process_handle();
        let mut threads = Vec::with_capacity(records.len());
        for record in records {
            let teb = self
                .client
                .server()
                .thread_data_offset(record.handle)
                .ok()
                .filter(|teb| *teb != 0);
            let start_address = self
                .client
                .server()
                .thread_start_address(process, record.handle)
                .ok()
                .filter(|address| *address != 0);
            threads.push(BackendThread {
                handle: record.handle,
                info: LiveUserThread {
                    tid: record.tid,
                    teb,
                    start_address,
                    name: None,
                },
            });
        }
        if let Some(current) = self.threads.get(self.current)
            && let Some(index) = threads
                .iter()
                .position(|thread| thread.info.tid == current.info.tid)
        {
            self.current = index;
        } else if self.current >= threads.len() {
            self.current = 0;
        }
        self.threads = threads;
        self.sync_live_threads();
        Ok(())
    }

    /// Read the debuggee's memory through the server.
    fn read_virtual(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.client
            .read_virtual(self.process_handle(), address, buf)
    }

    fn add_thread(&mut self, tid: u32, handle: u64, teb: u64, start_address: u64) {
        if self.threads.iter().any(|thread| thread.info.tid == tid) {
            return;
        }
        let start_address = (start_address != 0).then_some(start_address).or_else(|| {
            self.client
                .server()
                .thread_start_address(self.process_handle(), handle)
                .ok()
                .filter(|address| *address != 0)
        });
        self.threads.push(BackendThread {
            handle,
            info: LiveUserThread {
                tid,
                teb: (teb != 0).then_some(teb),
                start_address,
                name: None,
            },
        });
        self.sync_live_threads();
        // Debug registers are per thread: arm any existing watchpoints on the
        // newly arrived thread.
        for (slot, watch) in self.hardware.clone() {
            let _ = self.arm_slot_on_thread(handle, slot, Some(watch));
        }
    }

    fn remove_thread(&mut self, tid: u32) {
        if let Some(index) = self
            .threads
            .iter()
            .position(|thread| thread.info.tid == tid)
        {
            let removed = self.threads.remove(index);
            if self.current >= self.threads.len() {
                self.current = self.threads.len().saturating_sub(1);
            }
            if self.client.closes_handles() && removed.handle != 0 {
                let _ = self.client.server().close_handle(removed.handle);
            }
            self.sync_live_threads();
        }
    }

    /// Read a thread's `CONTEXT` into the architecture's register buffer.
    fn read_thread_context(&self, handle: u64) -> Result<Vec<u8>> {
        let flags = self.arch.context_flags();
        let (context, _used) = self.client.server().get_context(
            handle,
            flags.all,
            flags.offset as u32,
            self.arch.context_size() as u32,
        )?;
        Ok(self.arch.register_buffer(&context))
    }

    /// Write the `CONTEXT` prefix of `registers` back to `handle`.
    fn write_thread_context(&self, handle: u64, registers: &[u8]) -> Result<()> {
        let size = self.arch.context_size();
        if registers.len() < size {
            return Err(Error::Dbgsrv(format!(
                "a register write needs a {size}-byte CONTEXT, {} bytes given",
                registers.len()
            )));
        }
        let _used = self
            .client
            .server()
            .set_context(handle, &registers[..size])?;
        Ok(())
    }

    /// Read `handle`'s context, apply `edit`, and write it back.
    fn modify_thread_context(
        &self,
        handle: u64,
        edit: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<()> {
        let mut registers = self.read_thread_context(handle)?;
        edit(&mut registers)?;
        self.write_thread_context(handle, &registers)
    }

    /// Program slot `slot` in one thread's `CONTEXT`, or clear it.
    fn arm_slot_on_thread(
        &self,
        handle: u64,
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()> {
        self.modify_thread_context(handle, |registers| {
            self.arch
                .debug_registers()
                .arm(&self.register_map, registers, slot, watch)
        })
    }

    /// [`Self::arm_slot_on_thread`] on every thread of the process; reports the
    /// first failure after trying the rest.
    fn arm_slot_on_all_threads(&self, slot: usize, watch: Option<HardwareWatch>) -> Result<()> {
        let mut first_error = None;
        for thread in &self.threads {
            if let Err(error) = self.arm_slot_on_thread(thread.handle, slot, watch)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Set or clear the architecture's single-step flag on `handle` without
    /// altering `self.current`.
    fn set_step_flag(&self, handle: u64, enabled: bool) -> Result<()> {
        let flags = self.arch.flags_register();
        let mask = self.arch.single_step_flag_mask();
        self.modify_thread_context(handle, |registers| {
            let value = self.register_map.read_u64(flags, registers)?;
            let updated = if enabled { value | mask } else { value & !mask };
            self.register_map.write_u64(flags, registers, updated)
        })
    }

    /// Record a freshly observed stop, mark the target halted, and clear any
    /// armed single-step on the stopping thread.
    fn record_stop(&mut self, stop: StopEvent) -> StopEvent {
        self.stop = Some(stop.clone());
        self.running = false;
        if let Some(handle) = self.pending_step_thread(&stop) {
            self.armed_step = None;
            let _ = self.set_step_flag(handle, false);
        }
        stop
    }

    fn resume_with(&mut self, status: u32) -> Result<()> {
        self.require_alive()?;
        self.client.server().continue_event(status)?;
        self.running = true;
        self.stop = None;
        Ok(())
    }

    /// One `WaitForEvent`, decoded into the stop it reports. Non-stop events
    /// (debug output, thread creations and exits, other processes) are
    /// absorbed and continued here so the target never stalls on them.
    fn next_stop(&mut self, timeout_ms: u32) -> Result<Option<StopEvent>> {
        loop {
            // Release the connection lock before `absorb` issues follow-up RPCs.
            let event = self.client.server().wait_for_event(timeout_ms);
            let Some(bytes) = event? else {
                return Ok(None);
            };
            if let Some(stop) = self.absorb(&bytes)? {
                return Ok(Some(stop));
            }
        }
    }

    /// Fold one debug event into the target's state: `Some` when it is a stop
    /// the session should see, `None` after continuing an absorbed event.
    fn absorb(&mut self, bytes: &[u8]) -> Result<Option<StopEvent>> {
        let event = events::decode(bytes)?;
        let event_pid = event.process_id();
        if event_pid != self.pid && event_pid != 0 {
            // Another process the server also debugs: continue it so its
            // threads are not left frozen.
            let status = match event {
                DebugEvent::Exception { .. } => DBG_EXCEPTION_NOT_HANDLED,
                _ => DBG_CONTINUE,
            };
            self.client.server().continue_event(status)?;
            return Ok(None);
        }
        Ok(match event {
            DebugEvent::Exception {
                thread_id,
                record,
                first_chance,
                ..
            } => {
                let stop = StopEvent {
                    thread_id: Some(backend_thread_id(thread_id)),
                    exception_code: Some(record.code),
                    first_chance: Some(first_chance),
                    exception_address: Some(record.address),
                    program_counter: Some(record.address),
                    ..StopEvent::default()
                };
                self.last_exception = Some(record);
                Some(stop)
            }
            DebugEvent::CreateProcess {
                thread_id,
                process_handle,
                thread_handle,
                image_base,
                teb,
                ..
            } => {
                self.process.store(process_handle, Ordering::Release);
                self.live_state.update(|info| {
                    info.image_base = (image_base != 0).then_some(image_base);
                });
                self.add_thread(thread_id, thread_handle, teb, 0);
                self.modules_changed = true;
                Some(StopEvent {
                    thread_id: Some(backend_thread_id(thread_id)),
                    program_counter: Some(image_base),
                    ..StopEvent::default()
                })
            }
            DebugEvent::CreateThread {
                thread_id,
                handle,
                teb,
                start_address,
                ..
            } => {
                self.add_thread(thread_id, handle, teb, start_address);
                self.client.server().continue_event(DBG_CONTINUE)?;
                None
            }
            DebugEvent::ExitThread { thread_id, .. } => {
                self.remove_thread(thread_id);
                self.client.server().continue_event(DBG_CONTINUE)?;
                None
            }
            DebugEvent::ExitProcess { exit_code, .. } => {
                self.exit = Some(exit_code);
                Some(StopEvent {
                    process_exit: Some(exit_code),
                    ..StopEvent::default()
                })
            }
            DebugEvent::LoadDll { base, .. } => Some(self.module_stop(ModuleEvent::Load, base)),
            DebugEvent::UnloadDll { base, .. } => Some(self.module_stop(ModuleEvent::Unload, base)),
            DebugEvent::OutputDebugString {
                address,
                wide,
                length,
                ..
            } => {
                let text = self.read_debug_string(address, wide, length);
                self.debug_log.record(&text);
                self.client.server().continue_event(DBG_CONTINUE)?;
                None
            }
            DebugEvent::Rip { error, kind, .. } => {
                return Err(Error::Dbgsrv(format!(
                    "the process server lost the process (RIP event {kind}, error {error})"
                )));
            }
        })
    }

    fn module_stop(&mut self, kind: ModuleEvent, base: u64) -> StopEvent {
        self.modules_changed = true;
        StopEvent {
            modules_changed: true,
            module_event: Some(ModuleNotification {
                kind,
                base: VirtAddr(base),
                size: 0,
                path: None,
                process: Some(u64::from(self.pid)),
            }),
            ..StopEvent::default()
        }
    }

    /// Read a debug string the process printed (`OUTPUT_DEBUG_STRING_EVENT`).
    fn read_debug_string(&self, address: u64, wide: bool, length: u16) -> Vec<u8> {
        if address == 0 || length == 0 {
            return Vec::new();
        }
        let byte_len = if wide {
            usize::from(length) * 2
        } else {
            usize::from(length)
        };
        let mut buffer = vec![0u8; byte_len];
        if self.read_virtual(address, &mut buffer).is_err() {
            return Vec::new();
        }
        if wide {
            let mut bytes = utf16le_nul_terminated(&buffer).into_bytes();
            bytes.push(b'\n');
            return bytes;
        }
        buffer
    }

    /// The thread handle whose step trap this stop ended, if any.
    fn pending_step_thread(&self, stop: &StopEvent) -> Option<u64> {
        let armed = self.armed_step?;
        let tid = parse_backend_thread_id(stop.thread_id.as_deref()?)?;
        let thread = self.threads.iter().find(|thread| thread.info.tid == tid)?;
        (thread.handle == armed).then_some(armed)
    }

    /// Write the architecture's breakpoint instruction over the site's first
    /// bytes, keeping what it displaced.
    fn patch_site(&mut self, address: u64) -> Result<()> {
        if self.patched.contains_key(&address) {
            return Ok(());
        }
        let instruction = self.arch.breakpoint_instruction();
        let mut original = vec![0u8; instruction.len()];
        self.read_virtual(address, &mut original)?;
        self.client
            .write_virtual(self.process_handle(), address, instruction)?;
        self.patched.insert(address, original);
        Ok(())
    }

    /// Put the instruction [`Self::patch_site`] displaced back.
    fn restore_site(&mut self, address: u64) -> Result<()> {
        let Some(original) = self.patched.remove(&address) else {
            return Ok(());
        };
        self.client
            .write_virtual(self.process_handle(), address, &original)
            .map_err(|error| {
                Error::Dbgsrv(format!(
                    "cannot restore the instruction at {address:#x}: {error}"
                ))
            })
    }
}

impl DebugBackend for DbgsrvBackend {
    fn name(&self) -> &'static str {
        "dbgsrv"
    }

    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn registers_are_context(&self) -> bool {
        true
    }

    fn last_exception_record(&self) -> Option<ExceptionRecord> {
        self.last_exception.clone()
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        use DebugCapability::*;
        DebugCapability::matrix(|capability| match capability {
            MemoryIntrospection | ExecutionControl | InterruptTarget | SingleStep
            | ReadRegisters | WriteRegisters | ThreadList | ThreadSelection
            | UserModeBreakpoints | ModuleLoadEvents | DebugOutput => true,
            Watchpoints => self.supports_watchpoints(),
            _ => false,
        })
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.debug_log.read_since(since_seq)
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.require_alive()?;
        let handle = self.current_thread()?.handle;
        self.read_thread_context(handle)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.require_alive()?;
        let handle = self.current_thread()?.handle;
        self.write_thread_context(handle, data)
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        true
    }

    fn supports_watchpoints(&self) -> bool {
        self.client.generic_data_breakpoints()
            && self.arch.debug_registers().exposed_in(&self.register_map)
    }

    fn hardware_breakpoint_slots(&self) -> usize {
        self.arch.debug_registers().slots()
    }

    fn hardware_slot_range(&self, access: HwBreakpointAccess) -> Range<usize> {
        self.arch.debug_registers().slots_for(access)
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: usize,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        let slots = self.hardware_breakpoint_slots();
        if slot >= slots {
            return Err(invalid_slot(slot, slots));
        }
        let watch = HardwareWatch {
            address: addr,
            access,
            len,
        };
        self.arch.debug_registers().validate(watch)?;
        self.arm_slot_on_all_threads(slot, Some(watch))?;
        self.hardware.insert(slot, watch);
        Ok(())
    }

    fn clear_hardware_breakpoint(&mut self, slot: usize) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        self.arm_slot_on_all_threads(slot, None)?;
        self.hardware.remove(&slot);
        Ok(())
    }

    fn reclaims_abandoned_breakpoints(&self) -> bool {
        true
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.require_alive()?;
        if self.client.generic_code_breakpoints() {
            return self.patch_site(addr);
        }
        if self.service_plants.contains_key(&addr) {
            return Ok(());
        }
        let storage = self.client.server().insert_code_breakpoint(
            self.process_handle(),
            addr,
            self.client.info().machine_type,
        )?;
        self.service_plants.insert(addr, storage);
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.client.generic_code_breakpoints() {
            return self.restore_site(addr);
        }
        let Some(storage) = self.service_plants.remove(&addr) else {
            return Ok(());
        };
        self.client.server().remove_code_breakpoint(
            self.process_handle(),
            addr,
            self.client.info().machine_type,
            &storage,
        )
    }

    fn target_manages_breakpoint_sites(&self) -> bool {
        false
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.resume_with(DBG_CONTINUE)
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        self.resume_with(disposition.ntstatus())
    }

    fn step(&mut self) -> Result<()> {
        self.require_alive()?;
        let handle = self.current_thread()?.handle;
        self.set_step_flag(handle, true)?;
        self.armed_step = Some(handle);
        self.resume_with(DBG_CONTINUE)
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        if !self.running
            && let Some(stop) = &self.stop
        {
            return Ok(stop.clone());
        }
        self.require_alive()?;
        self.client
            .server()
            .request_break_in(self.process_handle())?;
        for _ in 0..BREAK_IN_TRIES {
            if let Some(stop) = self.next_stop(EVENT_POLL_MS)? {
                return Ok(self.record_stop(stop));
            }
        }
        Err(Error::Dbgsrv(format!(
            "the process did not break in after {BREAK_IN_TRIES} tries"
        )))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        if !self.running
            && let Some(stop) = &self.stop
        {
            return Ok(stop.clone());
        }
        let interrupt = Arc::clone(&self.interrupt);
        loop {
            if let Some(stop) = self.next_stop(EVENT_POLL_MS)? {
                return Ok(self.record_stop(stop));
            }
            if interrupt.swap(false, Ordering::SeqCst) {
                self.client
                    .server()
                    .request_break_in(self.process_handle())?;
            }
        }
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        if !self.running
            && let Some(stop) = &self.stop
        {
            return Ok(Some(stop.clone()));
        }
        let timeout = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let Some(stop) = self.next_stop(timeout.max(1))? else {
            return Ok(None);
        };
        Ok(Some(self.record_stop(stop)))
    }

    fn stop_kept(&self) -> bool {
        !self.running && self.stop.is_some()
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok(self
            .threads
            .iter()
            .map(|thread| backend_thread_id(thread.info.tid))
            .collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let tid = parse_backend_thread_id(thread_id).ok_or_else(|| {
            Error::Dbgsrv(format!(
                "thread id '{thread_id}' is not a hexadecimal thread id"
            ))
        })?;
        self.current = self
            .threads
            .iter()
            .position(|thread| thread.info.tid == tid)
            .ok_or_else(|| {
                Error::Dbgsrv(format!("process {} has no thread {thread_id}", self.pid))
            })?;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        if let Some(stop) = &self.stop
            && let Some(id) = &stop.thread_id
            && let Some(tid) = parse_backend_thread_id(id)
            && let Some(index) = self
                .threads
                .iter()
                .position(|thread| thread.info.tid == tid)
        {
            self.current = index;
            return Ok(id.clone());
        }
        self.threads
            .get(self.current)
            .map(|thread| backend_thread_id(thread.info.tid))
            .ok_or_else(|| Error::Dbgsrv(format!("process {} has no threads", self.pid)))
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn take_modules_changed(&mut self) -> bool {
        std::mem::take(&mut self.modules_changed)
    }

    fn prepare_for_exit(&mut self, _leave_running: bool) -> Result<()> {
        // The process outlives this session: restore every breakpoint and
        // watchpoint we planted, then detach so the process runs on cleanly.
        let process = self.process_handle();
        let machine_type = self.client.info().machine_type;
        for (address, original) in std::mem::take(&mut self.patched) {
            let _ = self.client.write_virtual(process, address, &original);
        }
        for (address, storage) in std::mem::take(&mut self.service_plants) {
            let _ = self.client.server().remove_code_breakpoint(
                process,
                address,
                machine_type,
                &storage,
            );
        }
        for slot in std::mem::take(&mut self.hardware).into_keys() {
            let _ = self.arm_slot_on_all_threads(slot, None);
        }
        if self.exit.is_none() {
            let _ = self.client.server().detach_process(self.pid);
        }
        self.running = false;
        Ok(())
    }
}
