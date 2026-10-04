//! Breakpoint and watchpoint management, deferred-breakpoint
//! reconciliation, and the automatic `nt!KeBugCheckEx` trap.

use std::mem::take;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::breakpoints::{
    Breakpoint, BreakpointConfig, BreakpointScope, HypercallFilter, ThreadScope, lift_target_site,
    plant_target_site,
};
use crate::dbg_backend::{
    BugcheckInfo, DebugCapability, HwBreakpointAccess, ModuleEvent, WatchpointAccess,
};
use crate::error::{Error, Result};
use crate::exception_policy::ExceptionPolicyMode;
use crate::expr::Expr;
use crate::guest::vm_exits::ExitFilter;
use crate::guest::{ModuleSymbolLoadReport, hypercalls};
use crate::partition_backend::PartitionBackend;
use crate::session::{ModuleTrap, Session, TrapSite};
use crate::types::{Arch, VirtAddr};

/// What [`Session::add_pattern_breakpoints`] set.
pub struct PatternBreakpoints {
    pub ids: Vec<u32>,
    /// Matches that failed to install, other than data symbols.
    pub errors: Vec<Error>,
    /// Whether the match count reached the limit, so more may match.
    pub limited: bool,
}

impl Session {
    /// Set a code breakpoint at `addr` with an optional display `symbol` and
    /// its configuration (condition, pass count, one-shot, command action;
    /// `BreakpointConfig::default()` for a plain one). The breakpoint's scope
    /// is derived from the current inspection context at install time.
    /// Returns the breakpoint id.
    pub fn add_breakpoint(
        &mut self,
        addr: VirtAddr,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.require_software_breakpoints()?;
        self.breakpoints
            .add_configured(self.backend.as_mut(), &self.target, addr, symbol, config)
    }

    /// Set a symbol-identity breakpoint: it survives module unload/reload and
    /// may remain deferred until matching symbols are loaded.
    pub fn add_symbol_breakpoint(
        &mut self,
        symbol: String,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.require_software_breakpoints()?;
        self.breakpoints
            .add_symbolic(self.backend.as_mut(), &self.target, symbol, config)
    }

    /// Set one source identity for every address matching `file:line`, or one
    /// deferred identity when no matching module is currently loaded. Returns
    /// one id per matching address (or the single deferred id).
    pub fn add_source_breakpoint(
        &mut self,
        source: String,
        config: BreakpointConfig,
    ) -> Result<Vec<u32>> {
        self.require_software_breakpoints()?;
        self.breakpoints
            .add_source(self.backend.as_mut(), &self.target, source, config)
    }

    /// Set one symbol-identity breakpoint per code symbol matching
    /// `pattern` (`bm`): `*`/`?` globs, optionally `module!`-qualified; at
    /// most `limit` matches. Data symbols the pattern also matches are
    /// skipped, as WinDbg's `bm` does. Returns the ids created and the
    /// errors of matches that failed to install.
    pub fn add_pattern_breakpoints(
        &mut self,
        pattern: &str,
        config: BreakpointConfig,
        limit: usize,
    ) -> Result<PatternBreakpoints> {
        self.require_software_breakpoints()?;
        let dtb = self.target.current_dtb();
        let names: Vec<String> = match pattern.split_once('!') {
            Some((module, query)) => self
                .target
                .symbols
                .search_symbols_in_module(dtb, module, query, limit)
                .into_iter()
                .map(|name| format!("{module}!{name}"))
                .collect(),
            None => self.target.current_symbol_index().search(pattern, limit),
        };
        let mut ids = Vec::new();
        let mut errors = Vec::new();
        let matched = names.len();
        for name in names.into_iter().take(limit) {
            let canonical = self
                .target
                .symbols
                .find_symbol_with_module(dtb, &name)?
                .map(|(_, module)| {
                    let bare = name
                        .rsplit_once('!')
                        .map_or(name.as_str(), |(_, bare)| bare);
                    format!("{module}!{bare}")
                })
                .unwrap_or_else(|| name.clone());
            match self.add_symbol_breakpoint(canonical, config.clone()) {
                Ok(id) => ids.push(id),
                Err(Error::NotCode { .. }) => {}
                Err(error) => errors.push(error),
            }
        }
        Ok(PatternBreakpoints {
            ids,
            errors,
            limited: matched >= limit,
        })
    }

    /// The `/p <pid>` breakpoint scope: hits are reported only from that
    /// process's address space.
    pub fn breakpoint_scope_for_pid(&self, pid: u64) -> Result<BreakpointScope> {
        let process = self
            .target
            .guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .enumerate_processes()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| Error::InvalidArgument(format!("process {pid} not found")))?;
        Ok(BreakpointScope::process(&process))
    }

    /// Arm the debugger's own kernel traps the backend needs: the bugcheck
    /// trap ([`Self::arm_bugcheck_trap`]), and the module traps while
    /// something waits on a load or unload ([`Self::sync_module_traps`]).
    /// Called at attach, where the operator can see them reported, and on
    /// every resume: the sites need kernel symbols, which can arrive late and
    /// move across a reboot, and the guest runs only after a resume, so that
    /// is where whether the module traps are wanted is decided.
    pub fn arm_traps(&mut self) {
        self.arm_bugcheck_trap();
        self.sync_module_traps();
    }

    /// Whether the backend reports `capability` as supported.
    fn backend_supports(&self, capability: DebugCapability) -> bool {
        self.backend
            .capabilities()
            .iter()
            .any(|entry| entry.capability == capability && entry.supported)
    }

    /// Arm an automatic breakpoint on `nt!KeBugCheckEx` when the backend
    /// cannot recognize a bugcheck on its own.
    ///
    /// KD learns of a crash from the target itself; a hypervisor stub never
    /// does, so the crash is only observable by stopping the guest as it
    /// enters the bugcheck.
    fn arm_bugcheck_trap(&mut self) {
        // A target that reports its own bugchecks needs no trap.
        if self.bugcheck_trap.is_some() || self.backend_supports(DebugCapability::BugcheckDetection)
        {
            return;
        }
        self.bugcheck_trap = self.plant_trap(
            "nt!KeBugCheckEx",
            "a bugcheck trap",
            "cannot detect a bugcheck by itself",
        );
    }

    /// Keep automatic breakpoints on the kernel functions that report a
    /// module `event`, exactly while that event is waited on, when the
    /// backend reports no module events on its own (see
    /// [`module_trap_symbols`] and [`Self::module_event_awaited`]).
    ///
    /// A load trap hit refreshes the module list, arms deferred breakpoints
    /// in the new image, and applies the `sx* ld` filters; an unload trap hit
    /// applies the `sx* ud` filters (see [`Self::classify_stop_event`]). The
    /// traps are not left in place otherwise: every driver load and unload
    /// runs them, and a trap a killed session leaves behind stops the next
    /// one with no debugger to take it.
    fn sync_module_traps(&mut self) {
        if self.backend_supports(DebugCapability::ModuleLoadEvents) {
            return;
        }
        for event in [ModuleEvent::Load, ModuleEvent::Unload] {
            let planted = self.module_traps.iter().any(|trap| trap.event == event);
            match (planted, self.module_event_awaited(event)) {
                (false, true) => {
                    let (what, needs) = match event {
                        ModuleEvent::Load => (
                            "a module-load trap",
                            "reports no module loads by itself; it stays while a breakpoint \
                             waits for its module or an sx ld filter is set",
                        ),
                        ModuleEvent::Unload => (
                            "a module-unload trap",
                            "reports no module unloads by itself; it stays while an sx ud \
                             filter is set",
                        ),
                    };
                    for symbol in module_trap_symbols(event) {
                        if let Some(site) = self.plant_trap(symbol, what, needs) {
                            self.module_traps.push(ModuleTrap { event, site });
                        }
                    }
                }
                (true, false) => self.lift_module_traps(event),
                _ => {}
            }
        }
    }

    /// Lift the traps for `event`. One that cannot be lifted stays, so a
    /// later resume tries again.
    fn lift_module_traps(&mut self, event: ModuleEvent) {
        let mut kept = Vec::new();
        for trap in take(&mut self.module_traps) {
            if trap.event != event {
                kept.push(trap);
                continue;
            }
            if let Err(error) =
                lift_target_site(self.backend.as_mut(), &self.target, trap.site.address)
            {
                self.notices.push(format!(
                    "failed to lift the module-{} trap: {error}",
                    event_word(event)
                ));
                kept.push(trap);
            }
        }
        self.module_traps = kept;
        // The other event's trap stays planted, and so does its marker.
        self.module_trap_interrupted
            .take_if(|(interrupted, _)| *interrupted == event);
    }

    /// Set an `sx* ld` or `sx* ud` filter.
    /// One that makes a GDB stub's module trap wanted while the target runs
    /// halts it briefly to plant the trap, so it applies to the next load or
    /// unload rather than only after the next resume.
    pub fn set_module_event_filter(
        &mut self,
        event: ModuleEvent,
        module: Option<String>,
        mode: ExceptionPolicyMode,
        command: Option<String>,
    ) -> Result<()> {
        self.exception_policies
            .set_module_event(event, module, mode, command);
        if !self.module_traps.iter().any(|trap| trap.event == event)
            && self.module_event_awaited(event)
            && !self.backend_supports(DebugCapability::ModuleLoadEvents)
        {
            self.with_target_halted(|session| {
                session.sync_module_traps();
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Whether something waits on a module `event`: an `sxe`/`sxn` filter
    /// for it, or for a load, a breakpoint not resolved yet.
    fn module_event_awaited(&self, event: ModuleEvent) -> bool {
        self.exception_policies.module_event_awaited(event)
            || (event == ModuleEvent::Load && self.breakpoints.list().iter().any(|bp| !bp.resolved))
    }

    /// Plant a debugger-owned breakpoint at the kernel `symbol`, reporting
    /// the outcome as `what` (`a bugcheck trap`) and why the backend `needs`
    /// it. `None` when the backend cannot hold a breakpoint, the kernel
    /// symbol is not known yet, or planting failed.
    fn plant_trap(&mut self, symbol: &str, what: &str, needs: &str) -> Option<TrapSite> {
        if !self.backend_supports(DebugCapability::KernelBreakpoints) {
            return None;
        }
        let kernel_dtb = self.target.guest.as_ref()?.ntoskrnl.dtb();
        let Ok(Some(address)) = self
            .target
            .symbols
            .find_symbol_across_modules(kernel_dtb, symbol)
        else {
            return None;
        };
        // Read the code before the trap displaces it: the stub writes the
        // breakpoint into guest memory, and memory here is read out of band
        // through the host mapping, so nothing else would ever see the
        // original instruction again.
        let mut original = vec![0u8; usize::from(self.target.arch().breakpoint_size())];
        if self
            .target
            .address_space(kernel_dtb)
            .read_bytes(address, &mut original)
            .is_err()
        {
            original.clear();
        }

        match plant_target_site(
            self.backend.as_mut(),
            &self.target,
            address,
            (!original.is_empty()).then_some(original.as_slice()),
        ) {
            Ok(()) => {
                self.notices.push(format!(
                    "armed {what} at {symbol} ({:#x}); the {} backend {needs}",
                    address.0,
                    self.backend.name()
                ));
                Some(TrapSite { address, original })
            }
            Err(error) => {
                self.notices
                    .push(format!("failed to arm {what} at {symbol}: {error}"));
                None
            }
        }
    }

    /// The bugcheck a [`Self::arm_bugcheck_trap`] stop is reporting, read
    /// from the arguments of the `KeBugCheckEx` call we stopped at.
    ///
    /// `nt!KiBugCheckData` is empty at the function's first instruction: the
    /// code that fills it has not run. The arguments have not been spilled
    /// yet either, so they are still in registers, the fifth on the stack
    /// above the shadow space.
    pub(super) fn bugcheck_from_trap(&mut self) -> Option<BugcheckInfo> {
        let registers = self.backend.read_registers().ok()?;
        let read = |name: &str| self.register_map.read_u64(name, &registers).ok();
        let (code, p1, p2, p3, p4) = match self.target.arch() {
            Arch::Amd64 => {
                let stack = read("rsp")?;
                let fourth = self
                    .target
                    .address_space(self.target.current_dtb())
                    .read::<u64>(VirtAddr(stack.wrapping_add(0x28)))
                    .ok();
                (read("rcx")?, read("rdx")?, read("r8")?, read("r9")?, fourth)
            }
            Arch::Arm64 => (
                read("x0")?,
                read("x1")?,
                read("x2")?,
                read("x3")?,
                read("x4"),
            ),
        };
        Some(BugcheckInfo {
            code: code as u32,
            parameters: [p1, p2, p3, p4.unwrap_or(0)],
            driver: None,
        })
    }

    /// The `/t` filter for an `ETHREAD`, for hosts that name a thread by
    /// address rather than by the REPL's selector grammar.
    pub fn breakpoint_thread_for_ethread(&self, ethread: u64) -> Result<ThreadScope> {
        let thread = self.target.thread_info_from_ethread(VirtAddr(ethread))?;
        Ok(ThreadScope::new(&thread))
    }

    /// Replace (or clear) a breakpoint's condition, compiling it with the
    /// default expression grammar.
    pub fn set_breakpoint_condition(&mut self, id: u32, condition: Option<String>) -> Result<()> {
        let compiled = condition
            .as_deref()
            .map(Expr::parse)
            .transpose()?
            .map(Arc::new);
        self.breakpoints.set_condition(id, condition, compiled)
    }

    /// Watch data accesses at `addr` (global across guest address spaces),
    /// with an optional host-resolved display symbol. Hosts choose write or
    /// read/write behavior while the backend implementation remains private.
    /// In a partition view, the watch is the partition's (see
    /// [`Self::add_hardware_breakpoint`]). Returns the stop-point id.
    pub fn add_watchpoint(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.add_hardware_breakpoint(addr, access.into(), len, symbol, config)
    }

    /// Set a debug-register breakpoint or data watch (`ba`) at `addr`, with
    /// an optional display `symbol`. Set in a partition view, it is the
    /// partition's: `addr` is the partition's, a hit by any other VP than
    /// the partition's is resumed, `/c` names a VP of it, and its thread
    /// filter and condition are checked in its view at the hit (see
    /// [`crate::breakpoints::PartitionFilter`]). Returns the id.
    pub fn add_hardware_breakpoint(
        &mut self,
        addr: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        let config = match self.partition() {
            Some(partition) => self.partition_breakpoint_config(partition, addr, config)?,
            None => config,
        };
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.add_hardware_configured(backend, target, addr, access, len, symbol, config)
    }

    /// Refuse a software breakpoint (`bp`, `bu`, `bm`) while a partition
    /// view is shown: one is planted through the target's page tables, never
    /// the partition's, while a debug register traps the partition's code.
    pub fn require_software_breakpoints(&self) -> Result<()> {
        match self.partition() {
            Some(partition) => Err(Error::Breakpoint(format!(
                "partition {partition:#x} takes only hardware breakpoints (ba e1 <address>): a software breakpoint is planted through the target's page tables, not the partition's"
            ))),
            None => Ok(()),
        }
    }

    /// Set a hypercall breakpoint (`!hvbp`): a hardware execute breakpoint on
    /// the handler the Windows hypervisor's hypercall table gives
    /// `filter.code`, whose hits stop only for that call from the caller
    /// `filter` names (see [`HypercallFilter::matches`]); the others are
    /// declined and the target resumed. Only a debug register the host
    /// programs traps in the hypervisor. A partition or VP the hypervisor
    /// does not have is refused, as a filter on it would never stop.
    /// Returns the breakpoint id.
    pub fn add_hypercall_breakpoint(
        &mut self,
        filter: HypercallFilter,
        config: BreakpointConfig,
    ) -> Result<u32> {
        if self.partition().is_some() {
            return Err(PartitionBackend::read_only("hypercall breakpoints"));
        }
        if !self.backend.hardware_breakpoints_trap_in_host() {
            return Err(Error::Breakpoint(
                "hypercall breakpoints need the gdb backend: only a debug register the host programs traps in the Windows hypervisor".into(),
            ));
        }
        self.require_hypervisor_caller(filter.partition, filter.vp)?;
        let (_, table) = self.target.hypercalls()?;
        let handler = table
            .get(usize::from(filter.code))
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "hypercall {:#06x} is beyond the hypervisor's table of {} codes",
                    filter.code,
                    table.len()
                ))
            })?
            .handler;
        let symbol = hypercalls::handler_name(&table, filter.code).map(|name| format!("hv!{name}"));
        self.breakpoints.add_hardware_configured(
            self.backend.as_mut(),
            &self.target,
            VirtAddr(handler),
            HwBreakpointAccess::Execute,
            1,
            symbol,
            BreakpointConfig {
                hypercall: Some(filter),
                ..config
            },
        )
    }

    /// Set a VM-exit breakpoint (`!hvexit`): a hardware execute breakpoint
    /// on the hypervisor's exit entry point ([`Target::vm_exit_entry`]),
    /// whose hits stop only for an exit with `filter.reason` from the caller
    /// `filter` names (see [`ExitFilter::matches`]); the others are declined
    /// and the target resumed. The entry runs for every exit, thousands a
    /// second, so the guest runs far slower while it is set. As for
    /// [`Self::add_hypercall_breakpoint`], a partition or VP the hypervisor
    /// does not have is refused. Returns the breakpoint id.
    pub fn add_exit_breakpoint(
        &mut self,
        filter: ExitFilter,
        config: BreakpointConfig,
    ) -> Result<u32> {
        if self.partition().is_some() {
            return Err(PartitionBackend::read_only("VM-exit breakpoints"));
        }
        if !self.backend.hardware_breakpoints_trap_in_host() {
            return Err(Error::Breakpoint(
                "VM-exit breakpoints need the gdb backend: only a debug register the host programs traps in the Windows hypervisor".into(),
            ));
        }
        self.require_hypervisor_caller(filter.partition, filter.vp)?;
        let entry = self.target.vm_exit_entry()?;
        self.breakpoints.add_hardware_configured(
            self.backend.as_mut(),
            &self.target,
            VirtAddr(entry),
            HwBreakpointAccess::Execute,
            1,
            Some("hv!VmExitEntry".to_string()),
            BreakpointConfig {
                vm_exit: Some(filter),
                ..config
            },
        )
    }

    /// Remove a breakpoint by id.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<()> {
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.remove(backend, target, id)
    }

    /// Refuse a hypervisor breakpoint's caller filter that could never
    /// match: a VP index without its partition, or a partition or VP the
    /// hypervisor does not have.
    fn require_hypervisor_caller(&self, partition: Option<u64>, vp: Option<u32>) -> Result<()> {
        if vp.is_some() && partition.is_none() {
            return Err(Error::InvalidArgument(
                "a VP index names a VP of one partition; give the partition ID too".into(),
            ));
        }
        let Some(id) = partition else {
            return Ok(());
        };
        let partitions = self.target.hypervisor_partitions()?;
        let partition = partitions
            .iter()
            .find(|partition| partition.id == id)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("the hypervisor has no partition {id:#x}"))
            })?;
        if let Some(vp) = vp
            && !partition
                .virtual_processors
                .iter()
                .any(|candidate| candidate.index == vp)
        {
            return Err(Error::InvalidArgument(format!(
                "partition {id:#x} has no VP {vp}"
            )));
        }
        Ok(())
    }

    /// Re-arm a disabled breakpoint (re-patch its `int3`).
    pub fn enable_breakpoint(&mut self, id: u32) -> Result<()> {
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.enable(backend, target, id)
    }

    /// Disable a breakpoint (restore the original byte) without forgetting it,
    /// so it can be re-enabled later.
    pub fn disable_breakpoint(&mut self, id: u32) -> Result<()> {
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.disable(backend, target, id)
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.list()
    }

    /// Return one breakpoint by id.
    pub fn breakpoint(&self, id: u32) -> Option<&Breakpoint> {
        self.breakpoints.list().into_iter().find(|bp| bp.id == id)
    }

    /// Put the original bytes of every debugger-owned site back into `buf`,
    /// read at `start` in the address space `dtb`: the manager's breakpoints
    /// and the session's own traps. Without this a view shows the debugger's
    /// `int3` instead of the guest's code. A partition view's memory holds
    /// none: its breakpoints are debug registers, and the sites are the
    /// target's.
    pub fn mask_code(&self, start: VirtAddr, buf: &mut [u8], dtb: u64) {
        if self.partition().is_some() {
            return;
        }
        self.breakpoints
            .mask_breakpoint_bytes(&self.target, start, buf, dtb);
        self.mask_traps(start, buf);
    }

    /// Put the traps' displaced instructions back into a read that covers
    /// them. The traps are not the manager's breakpoints, so the manager
    /// cannot mask them.
    fn mask_traps(&self, start: VirtAddr, buf: &mut [u8]) {
        let module_sites = self.module_traps.iter().map(|trap| &trap.site);
        for trap in self.bugcheck_trap.iter().chain(module_sites) {
            if trap.original.is_empty() || trap.address.0 < start.0 {
                continue;
            }
            let offset = (trap.address.0 - start.0) as usize;
            let end = offset + trap.original.len();
            if end <= buf.len() {
                buf[offset..end].copy_from_slice(&trap.original);
            }
        }
    }

    /// Uninstall every breakpoint. Successful removals are forgotten; failed
    /// removals remain managed so callers can retry and must not resume the
    /// target as if cleanup had succeeded.
    pub fn remove_all_breakpoints(&mut self) -> Result<()> {
        let (breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.remove_all(backend, target)
    }

    /// Whether any debugger-owned site is installed in the guest. The traps
    /// are not the manager's breakpoints, so a caller asking whether there is
    /// anything to restore has to ask for them too.
    pub fn has_installed_sites(&self) -> bool {
        !self.breakpoints.list().is_empty()
            || self.bugcheck_trap.is_some()
            || !self.module_traps.is_empty()
    }

    /// Take the automatic bugcheck and module traps back out of the
    /// guest.
    ///
    /// Nothing else does while the session lives: they are not the manager's
    /// breakpoints. Left behind, a trap is executed by the next thread to
    /// reach it with no debugger attached; if the session dies first, the
    /// site journal covers them.
    pub fn disarm_traps(&mut self) -> Result<()> {
        if let Some(trap) = &self.bugcheck_trap {
            lift_target_site(self.backend.as_mut(), &self.target, trap.address)?;
            self.bugcheck_trap = None;
        }
        while let Some(trap) = self.module_traps.last() {
            lift_target_site(self.backend.as_mut(), &self.target, trap.site.address)?;
            self.module_traps.pop();
        }
        self.module_trap_interrupted = None;
        Ok(())
    }

    /// Consult and clear the module-change signals, reconciling symbolic
    /// breakpoints when the module set moved. Returns whether it moved. The KD
    /// event signal and the per-stop module-list refresh are joined here so all
    /// hosts share the same deferred-breakpoint behavior; refresh and
    /// reconciliation failures are logged and do not discard the stop.
    pub fn refresh_modules_on_stop(&mut self) -> bool {
        let event_changed = self.backend.take_modules_changed()
            | std::mem::take(&mut self.unreported_module_change);
        let symbols_changed = match self.target.refresh_kernel_module_symbols() {
            Ok(report) => {
                let changed = report.loaded != 0 || report.unloaded != 0;
                if changed {
                    self.module_refresh_report = Some(report);
                }
                changed
            }
            Err(error) => {
                self.notices.push(format!(
                    "failed to refresh module symbols after module change: {error}"
                ));
                false
            }
        };
        let modules_changed = event_changed || symbols_changed;
        if modules_changed {
            self.reconcile_deferred_breakpoints();
        } else {
            self.reconcile_breakpoints_if_symbols_changed();
        }
        modules_changed
    }

    /// Re-resolve deferred (`bu`/source) breakpoints if any module's symbols
    /// became available since the last reconcile, whoever loaded them: a
    /// background fetch started by a stop render, a lazy frame load, or a
    /// process attach. Installing a site needs the target halted, so a running
    /// target waits for its next stop. Hosts call this after a command that
    /// may have loaded symbols; the stop path calls it on every stop.
    pub fn reconcile_breakpoints_if_symbols_changed(&mut self) {
        if self.target.symbols.load_generation() == self.symbols_reconciled_at
            || self.backend.is_running()
        {
            return;
        }
        self.reconcile_deferred_breakpoints();
    }

    fn reconcile_deferred_breakpoints(&mut self) {
        // Deferred breakpoints name the target's symbols; a partition view's
        // are another kernel's, which would move them into the wrong guest.
        if self.partition().is_some() {
            return;
        }
        // Read before reconciling: a fetch landing mid-reconcile is caught
        // next time rather than missed.
        self.symbols_reconciled_at = self.target.symbols.load_generation();
        if let Err(error) = self
            .breakpoints
            .reconcile_symbolic_after_module_refresh(self.backend.as_mut(), &self.target)
        {
            self.notices.push(format!(
                "failed to reconcile breakpoints after module refresh: {error}"
            ));
        }
    }

    /// Take the latest module-symbol report for the REPL's existing summary.
    /// The report is private to the REPL's summary path.
    pub fn take_module_refresh_report(&mut self) -> Option<ModuleSymbolLoadReport> {
        self.module_refresh_report.take()
    }
}

/// The kernel functions that report a module `event`, each taking the image
/// base as its second argument. The kernel calls `DbgLoadImageSymbols` for
/// every kernel image it maps, with the image listed in `PsLoadedModuleList`
/// and before its entry point runs, whether or not kernel debugging is
/// enabled; it is where KD's load notification comes from. An unload is
/// reported by `DbgUnLoadImageSymbolsUnicode` (current builds) or
/// `DbgUnLoadImageSymbols`, after the driver's unload routine and before the
/// image leaves the module list.
fn module_trap_symbols(event: ModuleEvent) -> &'static [&'static str] {
    match event {
        ModuleEvent::Load => &["nt!DbgLoadImageSymbols"],
        ModuleEvent::Unload => &[
            "nt!DbgUnLoadImageSymbols",
            "nt!DbgUnLoadImageSymbolsUnicode",
        ],
    }
}

/// `load` or `unload`, for messages about the module traps.
pub(super) fn event_word(event: ModuleEvent) -> &'static str {
    match event {
        ModuleEvent::Load => "load",
        ModuleEvent::Unload => "unload",
    }
}
