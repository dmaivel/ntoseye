//! A live user-mode target behind a DbgRpc process server: one process, its
//! threads, and its registers, with breakpoints patched into the process's
//! own code.
//!
//! The server supplies the primitives (`ReadVirtual`, `GetContext`,
//! `WaitForEvent`, ...); everything above — symbols, the Windows model,
//! stacks, the REPL — is the same code that inspects a user-mode minidump,
//! which is why this backend reports a user-mode context rather than a
//! processor one.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::arch::debug_registers::invalid_slot;
use crate::arch::{Arch, Family, HardwareWatch, HwBreakpointAccess, RegisterMap};
use crate::backend::dbg_backend::{
    BackendCapability, ContinueDisposition, DebugBackend, DebugCapability, DebugLog,
    DebugOutputPage, ModuleEvent, ModuleNotification, StopEvent,
};
use crate::base::error::{Error, Result};
use crate::base::ntstatus::STATUS_SINGLE_STEP;
use crate::base::types::VirtAddr;

use super::client::DbgSrvClient;
use super::events::{self, DebugEvent};
use super::service::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DEBUG_EVENT_SIZE, DEBUG_PROCESS_ONLY_THIS_PROCESS,
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

/// One thread of the debuggee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveThread {
    pub tid: u32,
    /// The process server's handle to the thread.
    pub handle: u64,
    /// The thread's `_TEB`, 0 when the server could not name it.
    pub teb: u64,
    /// The address the thread's function starts at, when the server says.
    pub start_address: Option<u64>,
}

/// The process a [`DbgsrvBackend`] debugs.
#[derive(Clone, Debug)]
pub struct LiveProcessInfo {
    pub pid: u32,
    pub process: u64,
    /// The process's `_PEB`, 0 when the server could not name it.
    pub peb: u64,
    pub threads: Vec<LiveThread>,
    pub selected_tid: Option<u32>,
    /// The image the process was created from, when the server named one.
    pub image_base: Option<u64>,
    /// The file name of the command line this session created, if any.
    pub image_hint: Option<String>,
}

/// What the debugger is attached to: an existing process, or one it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbgsrvTarget {
    /// `--process <pid>`: attach to a running process.
    Attach { pid: u32 },
    /// `--create <command line>`: start a process under the debugger.
    Create { command_line: String },
}

pub struct DbgsrvBackend {
    client: Arc<DbgSrvClient>,
    pid: u32,
    process: u64,
    peb: u64,
    arch: Arch,
    register_map: RegisterMap,
    threads: Vec<LiveThread>,
    current: usize,
    /// The stop the target is held at, when it is not running.
    stop: Option<StopEvent>,
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
    /// The thread whose trap flag (AMD64) or single-step bit (ARM64) is armed
    /// by a step that has not stopped yet.
    armed_step: Option<u64>,
    /// The watchpoints armed in this process's threads, by slot: the debug
    /// registers are per thread, so a thread created later is armed from
    /// here.
    hardware: BTreeMap<usize, HardwareWatch>,
    /// The image the process was created from, which is the only module a
    /// process has before its loader runs.
    image_base: Option<u64>,
    /// The file name of the command line this session created, used to name
    /// that image before its own headers can be read.
    image_hint: Option<String>,
}

impl DbgsrvBackend {
    /// Attach to, or create, the process `target` names, and hold it at its
    /// first debug event.
    pub fn connect(
        client: Arc<DbgSrvClient>,
        target: &DbgsrvTarget,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Self> {
        let arch = client.arch();
        let mut backend_image_hint: Option<String> = None;
        let (pid, process) = match target {
            DbgsrvTarget::Attach { pid } => {
                // Attach first: enumerating the machine's processes is a
                // separate privilege, and the attach itself says whether the
                // process is there.
                progress(&format!("dbgsrv: attaching to process {pid}"));
                let attached = client.server().attach_process(*pid, 0).map_err(|error| {
                    Error::DebugInfo(format!("dbgsrv process {pid} not found: {error}"))
                })?;
                (*pid, attached.handle)
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
                backend_image_hint = hint;
                (created.pid, created.process_handle)
            }
        };
        let mut backend = Self {
            client: client.clone(),
            pid,
            process,
            peb: 0,
            arch,
            register_map: arch.register_map().clone(),
            threads: Vec::new(),
            current: 0,
            stop: None,
            running: false,
            exit: None,
            patched: HashMap::new(),
            service_plants: HashMap::new(),
            debug_log: DebugLog::new(4096),
            modules_changed: false,
            interrupt: Arc::new(AtomicBool::new(false)),
            armed_step: None,
            hardware: BTreeMap::new(),
            image_base: None,
            image_hint: backend_image_hint.take(),
        };
        backend.peb = client.server().process_data_offset(process).unwrap_or(0);
        progress(&format!(
            "dbgsrv: process {pid} attached (handle {process:#x}, PEB {:#x})",
            backend.peb
        ));
        backend.reload_threads()?;
        progress(&format!("dbgsrv: {} thread(s)", backend.threads.len()));
        if backend.threads.is_empty() {
            progress(&format!(
                "dbgsrv: process {pid} lists no threads; select one with ~<n>s once it has one"
            ));
        }
        // The process's creation is already queued: it is the stop the target
        // sits at until a run command.
        let first = backend.next_stop(ATTACH_EVENT_MS)?;
        let Some(stop) = first else {
            return Err(Error::DebugInfo(
                "dbgsrv attach produced no initial debug event".to_string(),
            ));
        };
        backend.stop = Some(stop);
        backend.running = false;
        Ok(backend)
    }

    /// The stop the target is held at, if it has stopped since it last ran.
    pub fn current_stop(&self) -> Option<&StopEvent> {
        self.stop.as_ref()
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The process server's handle to the process, which its memory calls
    /// name.
    pub fn process_handle(&self) -> u64 {
        self.process
    }

    /// The live process as the target records it.
    pub fn live_process(&self) -> LiveProcessInfo {
        LiveProcessInfo {
            pid: self.pid,
            process: self.process,
            peb: self.peb,
            threads: self.threads.clone(),
            selected_tid: self.threads.get(self.current).map(|thread| thread.tid),
            image_base: self.image_base,
            image_hint: self.image_hint.clone(),
        }
    }

    /// The flag a host raises to interrupt work on this target: the stop wait
    /// breaks the process in when it sees it, and Ctrl+C raises it.
    pub fn interrupt_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupt)
    }

    pub fn client(&self) -> &Arc<DbgSrvClient> {
        &self.client
    }

    /// The backend id of `tid`, as `~` prints it: the thread id in hex.
    pub fn backend_thread_id(tid: u32) -> String {
        format!("{tid:x}")
    }

    fn require_alive(&self) -> Result<()> {
        match self.exit {
            Some(code) => Err(Error::DebugInfo(format!("dbgsrv process exited: {code}"))),
            None => Ok(()),
        }
    }

    fn current_thread(&self) -> Result<&LiveThread> {
        self.threads.get(self.current).ok_or_else(|| {
            Error::DebugInfo(format!(
                "dbgsrv process {} has no thread to inspect",
                self.pid
            ))
        })
    }

    /// Ask the server for the process's threads and their TEBs, growing the
    /// request once if it listed more than fit.
    fn reload_threads(&mut self) -> Result<()> {
        let mut wanted = THREAD_INFO_START;
        let (_, mut records, mut total) =
            self.client
                .server()
                .process_info(self.pid, PROC_INFO_NO_SUSPEND, wanted)?;
        if total > wanted {
            // A server naming more threads than a process can have is
            // corrupt: ask for the cap instead of allocating for the number.
            wanted = total.min(super::service::MAX_PROCESS_THREADS);
            let (_, more, count) =
                self.client
                    .server()
                    .process_info(self.pid, PROC_INFO_NO_SUSPEND, wanted)?;
            records = more;
            total = count;
        }
        let _ = total;
        records.truncate(wanted as usize);
        let mut threads = Vec::with_capacity(records.len());
        for record in records {
            let teb = self
                .client
                .server()
                .thread_data_offset(record.handle)
                .unwrap_or(0);
            let start_address = self
                .client
                .server()
                .thread_start_address(self.process, record.handle)
                .ok()
                .filter(|address| *address != 0);
            threads.push(LiveThread {
                tid: record.tid,
                handle: record.handle,
                teb,
                start_address,
            });
        }
        if let Some(current) = self.threads.get(self.current)
            && let Some(index) = threads.iter().position(|thread| thread.tid == current.tid)
        {
            self.current = index;
        } else if self.current >= threads.len() {
            self.current = 0;
        }
        self.threads = threads;
        Ok(())
    }

    /// Read the debuggee's memory through the server.
    fn read_virtual(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.client.read_virtual(self.process, address, buf)
    }

    fn add_thread(&mut self, tid: u32, handle: u64, teb: u64) {
        if self.threads.iter().any(|thread| thread.tid == tid) {
            return;
        }
        // The modern interface's `GetThreadBasicInfo` takes the process's
        // handle and then the thread's.
        let start_address = self
            .client
            .server()
            .thread_start_address(self.process, handle)
            .ok()
            .filter(|address| *address != 0);
        self.threads.push(LiveThread {
            tid,
            handle,
            teb,
            start_address,
        });
        // The debug registers are per thread: a thread this process creates
        // after a watchpoint was armed starts with none, so it is armed from
        // the same slot state now.
        for (slot, watch) in self.hardware.clone() {
            let _ = self.arm_slot_on_thread(handle, slot, Some(watch));
        }
    }

    /// Program slot `slot` in one thread's `CONTEXT`, or clear it.
    fn arm_slot_on_thread(
        &self,
        handle: u64,
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()> {
        let flags = self.arch.context_flags();
        let size = self.arch.context_size() as u32;
        let (context, _) =
            self.client
                .server()
                .get_context(handle, flags.all, flags.offset as u32, size)?;
        let mut registers = self.arch.register_buffer(&context);
        self.arch
            .debug_registers()
            .arm(&self.register_map, &mut registers, slot, watch)?;
        self.client
            .server()
            .set_context(handle, &registers[..self.arch.context_size()])?;
        Ok(())
    }

    /// [`Self::arm_slot_on_thread`] on every thread of the process: a watch
    /// has to be programmed in each thread's context, and a failure on any of
    /// them is reported once the rest were tried.
    fn arm_slot_on_all_threads(&self, slot: usize, watch: Option<HardwareWatch>) -> Result<()> {
        let mut first_error = None;
        for thread in &self.threads {
            if let Err(error) = self.arm_slot_on_thread(thread.handle, slot, watch)
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

    fn remove_thread(&mut self, tid: u32) {
        if let Some(index) = self.threads.iter().position(|thread| thread.tid == tid) {
            self.threads.remove(index);
            if self.current >= self.threads.len() {
                self.current = self.threads.len().saturating_sub(1);
            }
        }
    }

    /// One `WaitForEvent`, decoded into the stop it reports. Events that are
    /// not stops (debug output, a thread the session will list anyway) are
    /// absorbed here.
    fn next_stop(&mut self, timeout_ms: u32) -> Result<Option<StopEvent>> {
        loop {
            // The connection lock must die with this statement: `absorb`
            // makes calls of its own, and a `let ... else` keeps the
            // initializer's temporaries alive for the whole block.
            let event = self.client.server().wait_for_event(timeout_ms);
            let Some(bytes) = event? else {
                return Ok(None);
            };
            match self.absorb(&bytes)? {
                Some(stop) => return Ok(Some(stop)),
                None => continue,
            }
        }
    }

    /// Fold one debug event into the target's state: `Some` when it is a stop
    /// the session should see.
    fn absorb(&mut self, bytes: &[u8]) -> Result<Option<StopEvent>> {
        if bytes.len() < DEBUG_EVENT_SIZE as usize {
            return Err(Error::DebugInfo(format!(
                "dbgsrv: the server returned {} bytes of a debug event, {DEBUG_EVENT_SIZE} expected",
                bytes.len()
            )));
        }
        let event = events::decode(bytes)?;
        let event_pid = event.process_id();
        if event_pid != self.pid && event_pid != 0 {
            // Another process the server also debugs: take its events off the
            // queue and continue it, so its threads are not left stopped.
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
                code,
                flags,
                address,
                parameters,
                first_chance,
                ..
            } => {
                let mut event = empty_stop();
                event.thread_id = Some(Self::backend_thread_id(thread_id));
                event.exception_code = Some(code);
                event.first_chance = Some(first_chance);
                event.exception_address = Some(address);
                event.program_counter = Some(address);
                event.watchpoint_address = self.watchpoint_address(thread_id, code);
                let _ = (flags, parameters);
                Some(event)
            }
            DebugEvent::CreateProcess {
                thread_id,
                process_handle,
                thread_handle,
                image_base,
                teb,
                ..
            } => {
                self.process = process_handle;
                self.image_base = (image_base != 0).then_some(image_base);
                self.add_thread(thread_id, thread_handle, teb);
                self.modules_changed = true;
                let mut event = empty_stop();
                event.thread_id = Some(Self::backend_thread_id(thread_id));
                event.program_counter = Some(image_base);
                Some(event)
            }
            DebugEvent::CreateThread {
                thread_id,
                handle,
                teb,
                start_address,
                ..
            } => {
                self.add_thread(thread_id, handle, teb);
                let mut event = empty_stop();
                event.thread_id = Some(Self::backend_thread_id(thread_id));
                event.program_counter = (start_address != 0).then_some(start_address);
                Some(event)
            }
            DebugEvent::ExitThread { thread_id, .. } => {
                self.remove_thread(thread_id);
                None
            }
            DebugEvent::ExitProcess { exit_code, .. } => {
                self.exit = Some(exit_code);
                let mut event = empty_stop();
                event.exception_code = Some(exit_code);
                Some(event)
            }
            DebugEvent::LoadDll { base, .. } => {
                self.modules_changed = true;
                let mut event = empty_stop();
                event.modules_changed = true;
                event.module_event = Some(ModuleNotification {
                    kind: ModuleEvent::Load,
                    base: VirtAddr(base),
                    size: 0,
                    path: None,
                    process: Some(u64::from(self.pid)),
                });
                Some(event)
            }
            DebugEvent::UnloadDll { base, .. } => {
                self.modules_changed = true;
                let mut event = empty_stop();
                event.modules_changed = true;
                event.module_event = Some(ModuleNotification {
                    kind: ModuleEvent::Unload,
                    base: VirtAddr(base),
                    size: 0,
                    path: None,
                    process: Some(u64::from(self.pid)),
                });
                Some(event)
            }
            DebugEvent::OutputDebugString {
                address,
                wide,
                length,
                ..
            } => {
                let text = self.read_debug_string(address, wide, length);
                self.debug_log.record(&text);
                None
            }
            DebugEvent::Rip { error, kind, .. } => {
                return Err(Error::DebugInfo(format!(
                    "dbgsrv: the process server lost the process (RIP event {kind}, error {error})"
                )));
            }
        })
    }

    /// The data address a hardware data breakpoint trapped on, when the stop
    /// is one: [`STATUS_SINGLE_STEP`] is what a debug-register trap reports,
    /// and the server can say where.
    fn watchpoint_address(&mut self, tid: u32, code: u32) -> Option<u64> {
        // A single step is how both `t` and a `ba` hit report; only a server
        // that keeps data breakpoints of its own can name the address, and
        // the session reads it from the thread's DR6 anyway.
        if code != STATUS_SINGLE_STEP || self.client.generic_data_breakpoints() {
            return None;
        }
        let thread = self.threads.iter().find(|thread| thread.tid == tid)?;
        let (address, _access) = self
            .client
            .server()
            .last_data_breakpoint_hit(self.process, thread.handle)
            .ok()?;
        Some(address)
    }

    /// Read a debug string the process printed (`OUTPUT_DEBUG_STRING_EVENT`).
    fn read_debug_string(&self, address: u64, wide: bool, length: u16) -> Vec<u8> {
        if address == 0 || length == 0 {
            return Vec::new();
        }
        let bytes = if wide {
            (length as usize) * 2
        } else {
            length as usize
        };
        let mut buffer = vec![0u8; bytes];
        if self.read_virtual(address, &mut buffer).is_err() {
            return Vec::new();
        }
        if wide {
            let pairs = buffer.as_chunks::<2>().0;
            let wide: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
            let text = String::from_utf16_lossy(&wide);
            let mut bytes = text.into_bytes();
            bytes.push(b'\n');
            return bytes;
        }
        buffer
    }

    /// Arm the trap flag (AMD64) or the single-step bit (ARM64) on the current
    /// thread.
    fn arm_step(&mut self) -> Result<()> {
        let mut registers = self.read_registers()?;
        let flags = self.arch.flags_register();
        let mask = match self.arch.family() {
            Family::X86 => 1u64 << 8,
            Family::Arm => 1u64 << 21,
        };
        let value = self.register_map.read_u64(flags, &registers)?;
        self.register_map
            .write_u64(flags, &mut registers, value | mask)?;
        self.write_registers(&registers)?;
        self.armed_step = Some(self.current_thread()?.handle);
        Ok(())
    }

    /// Clear an armed step on `handle`, the thread a stop reported.
    fn disarm_step(&mut self, handle: u64) {
        if self.armed_step != Some(handle) {
            return;
        }
        self.armed_step = None;
        let Ok(mut registers) = self.current_or(handle).and_then(|_| self.read_registers()) else {
            return;
        };
        let flags = self.arch.flags_register();
        let mask = match self.arch.family() {
            Family::X86 => 1u64 << 8,
            Family::Arm => 1u64 << 21,
        };
        let Ok(value) = self.register_map.read_u64(flags, &registers) else {
            return;
        };
        if self
            .register_map
            .write_u64(flags, &mut registers, value & !mask)
            .is_err()
        {
            return;
        }
        let _ = self.write_registers(&registers);
    }

    /// Select the thread `handle` names, for the length of one register
    /// access.
    fn current_or(&mut self, handle: u64) -> Result<()> {
        if self.threads.get(self.current).map(|thread| thread.handle) != Some(handle) {
            let index = self
                .threads
                .iter()
                .position(|thread| thread.handle == handle)
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "dbgsrv process {} has no thread with handle {handle:#x}",
                        self.pid
                    ))
                })?;
            self.current = index;
        }
        Ok(())
    }
}

/// A [`StopEvent`] with every field at its inert value: what a stop that
/// carries only what its event said starts from.
fn empty_stop() -> StopEvent {
    StopEvent {
        thread_id: None,
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        watchpoint_address: None,
        is_bugcheck: false,
        break_in: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        module_event: None,
        assisted_breakin: false,
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

    fn capabilities(&self) -> Vec<BackendCapability> {
        use DebugCapability::*;
        [
            MemoryIntrospection,
            ExecutionControl,
            InterruptTarget,
            SingleStep,
            ReadRegisters,
            WriteRegisters,
            ThreadList,
            ThreadSelection,
            KernelBreakpoints,
            UserModeBreakpoints,
            Watchpoints,
            TargetReloadDetection,
            KernelBaseHint,
            BugcheckDetection,
            BugcheckDetails,
            ModuleLoadEvents,
            DebugOutput,
            Msr,
            IoPorts,
            PciConfig,
            TargetControl,
            TargetFileIo,
        ]
        .into_iter()
        .map(|capability| {
            let supported = match capability {
                MemoryIntrospection
                | ExecutionControl
                | InterruptTarget
                | SingleStep
                | ReadRegisters
                | WriteRegisters
                | ThreadList
                | ThreadSelection
                | UserModeBreakpoints
                // The service's `LoadDll`/`UnloadDll` events mark the module
                // list stale, and an `OUTPUT_DEBUG_STRING_EVENT` is kept in
                // the debug log. Both are a live process's own, not a
                // kernel's.
                | ModuleLoadEvents
                | DebugOutput => true,
                // `CONTEXT` carries the thread's debug registers, unless the
                // architecture's record has none.
                Watchpoints => self.supports_watchpoints(),
                _ => false,
            };
            BackendCapability {
                capability,
                supported,
            }
        })
        .collect()
    }

    fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.debug_log.read_since(since_seq)
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.require_alive()?;
        let thread = self.current_thread()?.handle;
        let flags = self.arch.context_flags();
        let (context, _used) = self.client.server().get_context(
            thread,
            flags.all,
            flags.offset as u32,
            self.arch.context_size() as u32,
        )?;
        Ok(self.arch.register_buffer(&context))
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        self.require_alive()?;
        let thread = self.current_thread()?.handle;
        let size = self.arch.context_size();
        if data.len() < size {
            return Err(Error::DebugInfo(format!(
                "dbgsrv: a register write needs a {size}-byte CONTEXT, {} bytes given",
                data.len()
            )));
        }
        let _used = self.client.server().set_context(thread, &data[..size])?;
        Ok(())
    }

    fn supports_user_mode_breakpoints(&self) -> bool {
        true
    }

    /// Whether this backend can install data watchpoints. A user-mode
    /// `CONTEXT` carries the thread's debug registers, so a slot is armed in
    /// each thread of the process; a target whose `ContextFlags` record no
    /// them (ARM64 wearing a WOW64 thread, say) cannot.
    fn supports_watchpoints(&self) -> bool {
        self.arch.debug_registers().exposed_in(&self.register_map)
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
        // Nothing replants what this session leaves: a journal entry is
        // keyed by the kernel a boot's pages belong to, which a user-mode
        // process has none of.
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
            self.process,
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
            self.process,
            addr,
            self.client.info().machine_type,
            &storage,
        )
    }

    fn target_manages_breakpoint_sites(&self) -> bool {
        false
    }

    fn continue_execution(&mut self) -> Result<()> {
        self.require_alive()?;
        self.client.server().continue_event(DBG_CONTINUE)?;
        self.running = true;
        self.stop = None;
        Ok(())
    }

    fn continue_execution_with_disposition(
        &mut self,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        let status = match disposition {
            ContinueDisposition::Handled => DBG_CONTINUE,
            ContinueDisposition::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
        };
        self.require_alive()?;
        self.client.server().continue_event(status)?;
        self.running = true;
        self.stop = None;
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        self.require_alive()?;
        self.arm_step()?;
        self.client.server().continue_event(DBG_CONTINUE)?;
        self.running = true;
        self.stop = None;
        Ok(())
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        if !self.running
            && let Some(stop) = &self.stop
        {
            return Ok(stop.clone());
        }
        self.require_alive()?;
        self.client.server().request_break_in(self.process)?;
        for _ in 0..BREAK_IN_TRIES {
            if let Some(stop) = self.next_stop(EVENT_POLL_MS)? {
                self.stop = Some(stop.clone());
                self.running = false;
                return Ok(stop);
            }
        }
        Err(Error::DebugInfo(format!(
            "dbgsrv: the process did not break in after {} tries",
            BREAK_IN_TRIES
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
                self.stop = Some(stop.clone());
                self.running = false;
                if let Some(handle) = self.pending_step_thread(&stop) {
                    self.disarm_step(handle);
                }
                return Ok(stop);
            }
            if interrupt.swap(false, Ordering::SeqCst) {
                self.client.server().request_break_in(self.process)?;
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
        self.stop = Some(stop.clone());
        self.running = false;
        if let Some(handle) = self.pending_step_thread(&stop) {
            self.disarm_step(handle);
        }
        Ok(Some(stop))
    }

    fn stop_kept(&self) -> bool {
        !self.running && self.stop.is_some()
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok(self
            .threads
            .iter()
            .map(|thread| Self::backend_thread_id(thread.tid))
            .collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let tid = u32::from_str_radix(thread_id, 16).map_err(|_| {
            Error::DebugInfo(format!(
                "dbgsrv thread id '{thread_id}' is not a hexadecimal thread id"
            ))
        })?;
        self.current = self
            .threads
            .iter()
            .position(|thread| thread.tid == tid)
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "dbgsrv process {} has no thread {thread_id}",
                    self.pid
                ))
            })?;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        if let Some(stop) = &self.stop
            && let Some(id) = &stop.thread_id
            && let Ok(tid) = u32::from_str_radix(id, 16)
            && let Some(index) = self.threads.iter().position(|thread| thread.tid == tid)
        {
            self.current = index;
            return Ok(id.clone());
        }
        self.threads
            .get(self.current)
            .map(|thread| Self::backend_thread_id(thread.tid))
            .ok_or_else(|| Error::DebugInfo(format!("dbgsrv process {} has no threads", self.pid)))
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn target_kernel_location(&mut self) -> Result<Option<crate::base::types::KernelLocation>> {
        Ok(None)
    }

    fn take_modules_changed(&mut self) -> bool {
        std::mem::take(&mut self.modules_changed)
    }

    fn prepare_for_exit(&mut self, _leave_running: bool) -> Result<()> {
        // The process outlives this session: put back every instruction this
        // one displaced, then let go of the process so it runs on.
        for (address, original) in std::mem::take(&mut self.patched) {
            let _ = self.client.write_virtual(self.process, address, &original);
        }
        self.service_plants.clear();
        if self.exit.is_none() {
            let _ = self.client.server().detach_process(self.pid);
        }
        self.running = false;
        Ok(())
    }
}

impl DbgsrvBackend {
    /// The thread handle whose step trap this stop ended, if any.
    fn pending_step_thread(&self, stop: &StopEvent) -> Option<u64> {
        let armed = self.armed_step?;
        let reported = stop.thread_id.as_deref()?;
        let tid = u32::from_str_radix(reported, 16).ok()?;
        let thread = self.threads.iter().find(|thread| thread.tid == tid)?;
        (thread.handle == armed).then_some(armed)
    }

    /// Write the architecture's breakpoint instruction over the site's first
    /// bytes, keeping what it displaced.
    fn patch_site(&mut self, address: u64) -> Result<()> {
        if self.patched.contains_key(&address) {
            return Ok(());
        }
        let instruction = self.arch.breakpoint_instruction().to_vec();
        let mut original = vec![0u8; instruction.len()];
        self.read_virtual(address, &mut original)?;
        self.client
            .write_virtual(self.process, address, &instruction)?;
        self.patched.insert(address, original);
        Ok(())
    }

    /// Put the instruction a [`Self::patch_site`] displaced back.
    fn restore_site(&mut self, address: u64) -> Result<()> {
        let Some(original) = self.patched.remove(&address) else {
            return Ok(());
        };
        self.client
            .write_virtual(self.process, address, &original)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "dbgsrv: cannot restore the instruction at {address:#x}: {error}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backend_thread_id_is_the_thread_id_in_hex() {
        assert_eq!(DbgsrvBackend::backend_thread_id(0x1a2c), "1a2c");
        assert_eq!(DbgsrvBackend::backend_thread_id(0x404), "404");
    }

    #[test]
    fn a_stop_starts_inert() {
        let stop = empty_stop();
        assert!(stop.thread_id.is_none());
        assert!(!stop.is_bugcheck);
        assert!(stop.module_event.is_none());
        assert!(!stop.modules_changed);
    }
}
