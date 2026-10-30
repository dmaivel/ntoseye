//! Breakpoint and watchpoint management, deferred-breakpoint
//! reconciliation, and the automatic `nt!KeBugCheckEx` trap.

use std::mem::take;
use std::sync::Arc;

use crate::arch::HwBreakpointAccess;
use crate::backend::dbg_backend::{BugcheckInfo, DebugCapability, ModuleEvent, WatchpointAccess};
use crate::backend::partition_backend::PartitionBackend;
use crate::base::error::{Error, Result};
use crate::base::memory::MemoryOps;
use crate::base::notice::Notice;
use crate::base::types::{Dtb, PhysAddr, VirtAddr};
use crate::nt::breakpoints::{
    BreakpointConfig, BreakpointInfo, BreakpointManager, BreakpointScope, BreakpointSpec,
    HypercallFilter, ThreadScope, lift_target_site, overlaps, plant_target_site, site_in_view,
    written_and_replanted,
};
use crate::nt::expr::Expr;
use crate::nt::guest::vm_exits::ExitFilter;
use crate::nt::guest::{ModuleSymbolLoadReport, ProcessInfo, hypercalls};
use crate::nt::symbols::split_query_module;
use crate::nt::target::{MemoryKind, Target};
use crate::session::exception_policy::ExceptionPolicyMode;
use crate::session::{ModuleTrap, Session, TrapSite};

/// What [`Session::add_pattern_breakpoints`] set.
pub struct PatternBreakpoints {
    pub ids: Vec<u32>,
    /// Matches that failed to install, other than data symbols.
    pub errors: Vec<Error>,
    /// Whether the match count reached the limit, so more may match.
    pub limited: bool,
}

/// A code breakpoint that [`Session::set_code_breakpoint`] or
/// [`Session::set_symbolic_breakpoint`] set, and why ntoseye could not
/// confirm that an instruction starts at its site, when it could not.
pub struct CheckedBreakpoint {
    pub id: u32,
    pub warning: Option<String>,
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
        self.breakpoints.edit().add_configured(
            self.backend.as_mut(),
            &self.target,
            addr,
            symbol,
            config,
        )
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
            .edit()
            .add_symbolic(self.backend.as_mut(), &self.target, symbol, config)
    }

    /// Set a software breakpoint at `address` as `bp` does, for every host
    /// that takes the address from a user: an instruction must start there
    /// ([`Self::check_instruction_start`]) unless `config.unchecked` (`/a`),
    /// and the breakpoint is labelled by the closest symbol in the address
    /// space its scope resolves in.
    pub fn set_code_breakpoint(
        &mut self,
        address: VirtAddr,
        config: BreakpointConfig,
    ) -> Result<CheckedBreakpoint> {
        self.require_software_breakpoints()?;
        let dtb = BreakpointManager::resolution_dtb(&self.target, config.scope.as_ref());
        let warning = if config.unchecked {
            None
        } else {
            self.check_instruction_start(dtb, address)?
        };
        let symbol = self
            .target
            .symbols
            .format_closest_symbol_for_address(dtb, address);
        let id = self.breakpoints.edit().add_configured(
            self.backend.as_mut(),
            &self.target,
            address,
            symbol,
            config,
        )?;
        Ok(CheckedBreakpoint { id, warning })
    }

    /// Set a symbolic breakpoint as `bu` does, for every host that takes the
    /// spec from a user: a symbol with an offset must name the start of an
    /// instruction, checked as [`Self::set_code_breakpoint`] checks an
    /// address, unless `config.unchecked`.
    pub fn set_symbolic_breakpoint(
        &mut self,
        spec: String,
        config: BreakpointConfig,
    ) -> Result<CheckedBreakpoint> {
        self.require_software_breakpoints()?;
        let warning = if config.unchecked {
            None
        } else {
            self.check_symbol_site(&spec, config.scope.as_ref())?
        };
        let id = self.breakpoints.edit().add_symbolic(
            self.backend.as_mut(),
            &self.target,
            spec,
            config,
        )?;
        Ok(CheckedBreakpoint { id, warning })
    }

    /// Check that an instruction starts where a symbolic breakpoint's `spec`
    /// resolves in `scope`. A symbol's own start always is one, but an
    /// offset into a symbol that does not resolve yet cannot be checked,
    /// which the warning says.
    fn check_symbol_site(
        &self,
        spec: &str,
        scope: Option<&BreakpointScope>,
    ) -> Result<Option<String>> {
        let target = &self.target;
        match BreakpointManager::resolve_symbol_in_scope(target, spec, scope)? {
            Some((_, 0)) => Ok(None),
            Some((address, _)) => self
                .check_instruction_start(BreakpointManager::resolution_dtb(target, scope), address),
            None => match BreakpointSpec::split_symbol_offset(spec) {
                Some((symbol, offset)) if offset != 0 => Ok(Some(format!(
                    "{} does not resolve yet, so ntoseye could not check that an instruction starts \
                     at {spec}",
                    symbol.trim(),
                ))),
                _ => Ok(None),
            },
        }
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
            .edit()
            .add_source(self.backend.as_mut(), &self.target, source, config)
    }

    /// Set one symbol-identity breakpoint per code symbol matching
    /// `pattern` (`bm`): `*`/`?` globs, optionally `module!`-qualified; at
    /// most `limit` matches. Data symbols the pattern also matches are
    /// skipped, as WinDbg's `bm` does. Returns the ids created and the
    /// errors of matches that failed to install. A `/p` scope searches that
    /// process's modules ([`Self::in_breakpoint_scope`]).
    pub fn add_pattern_breakpoints(
        &mut self,
        pattern: &str,
        config: BreakpointConfig,
        limit: usize,
    ) -> Result<PatternBreakpoints> {
        self.require_software_breakpoints()?;
        let scope = config.scope.as_ref();
        let (names, matched) = self.in_breakpoint_scope(scope, |target| {
            let module = split_query_module(pattern);
            // `.process /p` would load every module's symbols; the pattern
            // names the modules it searches. A process whose loader list
            // cannot be read (a kernel-only one) has only what is loaded.
            if let Some(BreakpointScope::Process { pid, dtb, .. }) = scope {
                let _ = target.load_process_module_symbols(
                    *pid,
                    *dtb,
                    module.map(|(module, _)| module),
                );
            }
            let dtb = target.current_dtb();
            let names = match module {
                Some((module, query)) => target
                    .symbols
                    .search_symbols_in_modules(dtb, module, query, limit),
                None => target.current_symbol_index().search(pattern, limit),
            };
            let matched = names.len();
            let canonical = names
                .into_iter()
                .take(limit)
                .map(|name| {
                    Ok(target
                        .symbols
                        .find_symbol_with_module(dtb, &name)?
                        .map(|(_, module)| {
                            let bare = name
                                .rsplit_once('!')
                                .map_or(name.as_str(), |(_, bare)| bare);
                            format!("{module}!{bare}")
                        })
                        .unwrap_or_else(|| name.clone()))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((canonical, matched))
        })?;
        let mut ids = Vec::new();
        let mut errors = Vec::new();
        for canonical in names {
            match self.add_symbol_breakpoint(canonical, config.clone()) {
                Ok(id) => ids.push(id),
                Err(Error::NotCode { .. }) => {}
                // Every later match would fail the same way.
                Err(error @ Error::BreakpointTableFull(_)) => {
                    errors.push(error);
                    break;
                }
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
        self.process_for_pid(pid)
            .map(|process| BreakpointScope::process(&process))
    }

    fn process_for_pid(&self, pid: u64) -> Result<ProcessInfo> {
        self.target
            .guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .enumerate_processes()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| Error::InvalidArgument(format!("process {pid} not found")))
    }

    /// Resolve a breakpoint's address with `resolve` in the address space
    /// its `scope` names, as [`Self::in_breakpoint_scope`] does, so `ba e1
    /// /p 4 kernelbase!SleepEx+0x60` needs no `.process` around it. When
    /// `resolve` misses a symbol of a module the `/p` process maps, that
    /// module's symbols are loaded and `resolve` runs again.
    pub fn resolve_in_breakpoint_scope<T>(
        &mut self,
        scope: Option<&BreakpointScope>,
        resolve: impl Fn(&Target) -> Result<T>,
    ) -> Result<T> {
        let process = match scope {
            Some(BreakpointScope::Process { pid, dtb, .. }) => Some((*pid, *dtb)),
            _ => None,
        };
        self.in_breakpoint_scope(scope, |target| {
            loop {
                let result = resolve(target);
                // Each load attempts modules not tried before, so this ends.
                if let (Err(Error::SymbolNotFound(name)), Some((pid, dtb))) = (&result, process)
                    && let Some((module, _)) = name.split_once('!')
                    && matches!(
                        target.load_process_module_symbols(pid, dtb, Some(module.trim())),
                        Ok(true)
                    )
                {
                    continue;
                }
                return result;
            }
        })
    }

    /// Run `f` in the address space a breakpoint's `scope` names: for `/p
    /// <pid>`, that process's, as `.process /p` selects it, with the
    /// selection put back afterwards; otherwise the current context, where
    /// a kernel symbol resolves as anywhere.
    fn in_breakpoint_scope<R>(
        &mut self,
        scope: Option<&BreakpointScope>,
        f: impl FnOnce(&Target) -> Result<R>,
    ) -> Result<R> {
        match scope {
            Some(BreakpointScope::Process { pid, .. }) => {
                let process = self.process_for_pid(*pid)?;
                self.target.in_process_scope(process, f)
            }
            _ => f(&self.target),
        }
    }

    /// Arm the debugger's own kernel traps the backend needs: the bugcheck
    /// trap ([`Self::arm_bugcheck_trap`]), and the module traps while
    /// something waits on a load or unload ([`Self::sync_module_traps`]);
    /// and tell it where the kernel's break-ins land. Called at attach,
    /// where the operator can see them reported, and on every resume: the
    /// sites need kernel symbols, which can arrive late and move across a
    /// reboot, and the guest runs only after a resume, so that is where
    /// whether the module traps are wanted is decided.
    pub fn arm_traps(&mut self) {
        self.rearm_dropped_traps();
        self.arm_bugcheck_trap();
        self.sync_module_traps();
        self.note_breakin_site();
    }

    /// Plant again the traps a stop's report took out of the target's table
    /// (see [`crate::backend::dbg_backend::DebugBackend::sites_dropped_by_stop`]),
    /// as [`BreakpointManager::refresh_enabled`] does the manager's
    /// breakpoints: otherwise their events stop being reported.
    fn rearm_dropped_traps(&mut self) {
        let dropped = self.backend.sites_dropped_by_stop();
        if dropped.is_empty() {
            return;
        }
        let module_sites = self.module_traps.iter().map(|trap| &trap.site);
        let sites: Vec<TrapSite> = self
            .bugcheck_trap
            .iter()
            .chain(module_sites)
            .filter(|trap| dropped.contains(&trap.address.0))
            .cloned()
            .collect();
        for trap in sites {
            let original = (!trap.original.is_empty()).then_some(trap.original.as_slice());
            if let Err(error) =
                plant_target_site(self.backend.as_mut(), &self.target, trap.address, original)
            {
                self.notices.push(Notice::warning(format!(
                    "failed to re-arm the trap at {:#x} its stop dropped: {error}",
                    trap.address.0
                )));
            }
        }
    }

    /// Name the kernel's break-in site to the backend (see
    /// [`crate::backend::dbg_backend::DebugBackend::note_breakin_site`]). A KD connect learns it from its
    /// first stop, which is somewhere else when the target was already
    /// halted at a break of its own; the break-in the connect sent is then
    /// still pending, and would stop the first resume there.
    fn note_breakin_site(&mut self) {
        let Some(kernel_dtb) = self.target.guest.as_ref().map(|guest| guest.ntoskrnl.dtb()) else {
            return;
        };
        if let Ok(Some(address)) = self
            .target
            .symbols
            .find_symbol_across_modules(kernel_dtb, "nt!DbgBreakPointWithStatus")
        {
            self.backend.note_breakin_site(address.0);
        }
    }

    /// Arm an automatic breakpoint on `nt!KeBugCheckEx` when the backend
    /// cannot recognize a bugcheck on its own.
    ///
    /// KD learns of a crash from the target itself; a hypervisor stub never
    /// does, so the crash is only observable by stopping the guest as it
    /// enters the bugcheck.
    fn arm_bugcheck_trap(&mut self) {
        // A target that reports its own bugchecks needs no trap.
        if self.bugcheck_trap.is_some() || self.backend.supports(DebugCapability::BugcheckDetection)
        {
            return;
        }
        let trap = self.plant_trap(
            "nt!KeBugCheckEx",
            "a bugcheck trap",
            "cannot detect a bugcheck by itself",
        );
        *self.bugcheck_trap.edit() = trap;
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
        self.sync_user_image_trap();
        if self.backend.supports(DebugCapability::ModuleLoadEvents) {
            return;
        }
        for event in [ModuleEvent::Load, ModuleEvent::Unload] {
            let planted = self
                .module_traps
                .iter()
                .any(|trap| trap.event == event && !trap.user);
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
                            self.module_traps.edit().push(ModuleTrap {
                                event,
                                site,
                                user: false,
                            });
                        }
                    }
                }
                (true, false) => self.lift_module_traps(event, false),
                _ => {}
            }
        }
    }

    /// Keep the user-image trap ([`USER_IMAGE_TRAP`]) exactly while a
    /// user-mode image load is waited on ([`Self::user_image_load_awaited`]).
    /// Windows reports user-mode images to a kernel debugger only with
    /// `!gflag +ksl`, and then only an image's first mapping; the trap sees
    /// every mapping, in every process, on every backend. Each one halts the
    /// target while the trap is planted.
    fn sync_user_image_trap(&mut self) {
        let planted = self.module_traps.iter().any(|trap| trap.user);
        match (planted, self.user_image_load_awaited()) {
            (false, true) => {
                if let Some(site) = self.plant_trap(
                    USER_IMAGE_TRAP,
                    "a user-image load trap",
                    "reports no user-mode image loads by itself; it stays while a breakpoint \
                     scoped to a process waits for its module or an sx ld filter can name a DLL",
                ) {
                    self.module_traps.edit().push(ModuleTrap {
                        event: ModuleEvent::Load,
                        site,
                        user: true,
                    });
                }
            }
            (true, false) => self.lift_module_traps(ModuleEvent::Load, true),
            _ => {}
        }
    }

    /// Whether something waits on a user-mode image load: a deferred
    /// breakpoint scoped to a process, or an `sxe`/`sxn ld` filter that can
    /// name one (bare `ld`, or a module that is not a `.sys` driver).
    fn user_image_load_awaited(&self) -> bool {
        self.breakpoints
            .list()
            .iter()
            .any(|bp| !bp.resolved && matches!(bp.scope, BreakpointScope::Process { .. }))
            || self
                .exception_policies
                .module_event_entries()
                .any(|policy| {
                    policy.event == ModuleEvent::Load
                        && matches!(
                            policy.mode,
                            ExceptionPolicyMode::Break | ExceptionPolicyMode::Notify
                        )
                        && policy
                            .module
                            .as_deref()
                            .is_none_or(|module| !module.to_ascii_lowercase().ends_with(".sys"))
                })
    }

    /// Whether the user-image trap is planted.
    pub fn user_image_trap_planted(&self) -> bool {
        self.module_traps.iter().any(|trap| trap.user)
    }

    /// Lift the traps for `event` (the user-image one, or the others). One
    /// that cannot be lifted stays, so a later resume tries again.
    fn lift_module_traps(&mut self, event: ModuleEvent, user: bool) {
        let mut kept = Vec::new();
        let traps = take(&mut *self.module_traps.edit());
        for trap in traps {
            if trap.event != event || trap.user != user {
                kept.push(trap);
                continue;
            }
            if let Err(error) =
                lift_target_site(self.backend.as_mut(), &self.target, trap.site.address)
            {
                self.notices.push(Notice::warning(format!(
                    "failed to lift the module-{} trap: {error}",
                    event_word(event)
                )));
                kept.push(trap);
            }
        }
        *self.module_traps.edit() = kept;
        // The other traps stay planted, and so do their markers.
        self.module_trap_interrupted
            .take_if(|(interrupted, trap_user, _)| *interrupted == event && *trap_user == user);
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
        let kernel_trap_wanted = !self
            .module_traps
            .iter()
            .any(|trap| trap.event == event && !trap.user)
            && self.module_event_awaited(event)
            && !self.backend.supports(DebugCapability::ModuleLoadEvents);
        let user_trap_wanted = !self.user_image_trap_planted() && self.user_image_load_awaited();
        if kernel_trap_wanted || user_trap_wanted {
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
        if !self.backend.supports(DebugCapability::KernelBreakpoints) {
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
                self.notices.push(Notice::info(format!(
                    "armed {what} at {symbol} ({:#x}); the {} backend {needs}",
                    address.0,
                    self.backend.name()
                )));
                Some(TrapSite { address, original })
            }
            Err(error) => {
                self.notices.push(Notice::warning(format!(
                    "failed to arm {what} at {symbol}: {error}"
                )));
                None
            }
        }
    }

    /// The bugcheck a [`Self::arm_bugcheck_trap`] stop is reporting, read
    /// from the arguments of the `KeBugCheckEx` call we stopped at.
    ///
    /// `nt!KiBugCheckData` is empty at the function's first instruction: the
    /// code that fills it has not run. The arguments have not been spilled
    /// yet either, so they are where the calling convention put them.
    pub(super) fn bugcheck_from_trap(&mut self) -> Option<BugcheckInfo> {
        let registers = self.backend.read_registers().ok()?;
        let argument = |index| {
            self.argument_on_entry(index, |name| {
                self.register_map.read_u64(name, &registers).ok()
            })
        };
        Some(BugcheckInfo {
            code: argument(0)? as u32,
            parameters: [
                argument(1)?,
                argument(2)?,
                argument(3)?,
                argument(4).unwrap_or(0),
            ],
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
        self.breakpoints
            .edit()
            .set_condition(id, condition, compiled)
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

    /// Set a debug-register breakpoint or data watch as `ba` does, for every
    /// host that takes the address from a user: labelled by the closest
    /// symbol in the address space its scope resolves in (see
    /// [`Self::add_hardware_breakpoint`]).
    pub fn set_hardware_breakpoint(
        &mut self,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        config: BreakpointConfig,
    ) -> Result<u32> {
        let dtb = BreakpointManager::resolution_dtb(&self.target, config.scope.as_ref());
        let symbol = self
            .target
            .symbols
            .format_closest_symbol_for_address(dtb, address);
        self.add_hardware_breakpoint(address, access, len, symbol, config)
    }

    /// Set a debug-register breakpoint or data watch (`ba`) at `addr`, with
    /// an optional display `symbol`. Set in a partition view, it is the
    /// partition's: `addr` is the partition's, a hit by any other VP than
    /// the partition's is resumed, `/c` names a VP of it, and its thread
    /// filter and condition are checked in its view at the hit (see
    /// [`crate::nt::breakpoints::PartitionFilter`]). In VTL1 it is global: NT's
    /// processes and threads say nothing about which VTL1 context executes
    /// an address, so a process or thread filter is refused. Returns the id.
    pub fn add_hardware_breakpoint(
        &mut self,
        addr: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        if self.target.in_secure_address_space()
            && (matches!(config.scope, Some(BreakpointScope::Process { .. }))
                || config.thread.is_some())
        {
            return Err(Error::Breakpoint(
                "a VTL1 hardware breakpoint is global: a process or thread filter (/p, /t) \
                 names NT's processes and threads"
                    .to_string(),
            ));
        }
        let config = match self.partition() {
            Some(partition) => self.partition_breakpoint_config(partition, addr, config)?,
            None => config,
        };
        let (mut breakpoints, backend, target) = self.breakpoint_sites();
        if access == HwBreakpointAccess::Execute
            && backend.debug_traps_reach_target()
            && let Some(refusal) = target.breakpoint_site_refusal(addr)
        {
            return Err(Error::Breakpoint(refusal));
        }
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
        self.breakpoints.edit().add_hardware_configured(
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
        self.breakpoints.edit().add_hardware_configured(
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
        let (mut breakpoints, backend, target) = self.breakpoint_sites();
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
        let (mut breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.enable(backend, target, id)
    }

    /// Disable a breakpoint (restore the original byte) without forgetting it,
    /// so it can be re-enabled later.
    pub fn disable_breakpoint(&mut self, id: u32) -> Result<()> {
        let (mut breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.disable(backend, target, id)
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<&BreakpointInfo> {
        self.breakpoints.list()
    }

    /// Return one breakpoint by id.
    pub fn breakpoint(&self, id: u32) -> Option<&BreakpointInfo> {
        self.breakpoints.list().into_iter().find(|bp| bp.id == id)
    }

    /// Write `data` at `address` of `memory`: the inspection address space
    /// ([`Self::write_in`]), or guest-physical memory. Every host's memory
    /// write (`eb`, `!eb`, `f`, `Memory.write`, a DAP `writeMemory`, a gdb
    /// `M` packet) goes through it or [`Self::write_in`].
    pub fn write_memory(&mut self, memory: MemoryKind, address: u64, data: &[u8]) -> Result<()> {
        match memory {
            MemoryKind::Virtual => {
                self.write_in(self.target.current_dtb(), VirtAddr(address), data)
            }
            MemoryKind::Physical => {
                let sites = |session: &Session| {
                    if session.partition().is_some() {
                        return Default::default();
                    }
                    let kernel = session.target.kernel_address_space();
                    let traps = session.trap_sites_under(address, data.len(), |trap| {
                        let translation = kernel.virt_to_phys(trap).ok().flatten()?;
                        Some(translation.address)
                    });
                    let ids = session.breakpoints.sites_under_physical_write(
                        &session.target,
                        address,
                        data.len(),
                    );
                    (ids, traps)
                };
                self.write_around_sites(sites, |target| target.write_physical(address, data))
            }
        }
    }

    /// Write `data` at `address` in the address space `dtb` as
    /// [`Target::read_masked_in`] reads it: where the write lands on one of
    /// this session's breakpoints or traps, it replaces the code the site
    /// displaced, and the site stays planted over the new code.
    pub fn write_in(&mut self, dtb: Dtb, address: VirtAddr, data: &[u8]) -> Result<()> {
        // The same sites a read masks (see `CodeSites::mask`): a trap is
        // kernel code, under the write where `dtb` reaches its kernel frame.
        let sites = |session: &Session| {
            if session.partition().is_some() || session.target.symbols.is_secure_root(dtb) {
                return Default::default();
            }
            let target = &session.target;
            let traps = session.trap_sites_under(address.0, data.len(), |trap| {
                site_in_view(target, trap, None, dtb).then_some(trap.0)
            });
            let ids = session
                .breakpoints
                .sites_under_write(target, dtb, address, data.len());
            (ids, traps)
        };
        self.write_around_sites(sites, |target| {
            target.address_space(dtb).write_bytes(address, data)
        })
    }

    /// The traps a write of `len` bytes at `start` lands on, where `locate`
    /// says where a trap's site is in the write's address space (`None`: it
    /// is not there).
    fn trap_sites_under(
        &self,
        start: u64,
        len: usize,
        locate: impl Fn(VirtAddr) -> Option<u64>,
    ) -> Vec<VirtAddr> {
        let site_len = usize::from(self.target.arch().breakpoint_size());
        let module_sites = self.module_traps.iter().map(|trap| &trap.site);
        self.bugcheck_trap
            .iter()
            .chain(module_sites)
            .map(|trap| trap.address)
            .filter(|&address| {
                locate(address)
                    .is_some_and(|site| overlaps(VirtAddr(start), len, VirtAddr(site), site_len))
            })
            .collect()
    }

    /// Run `write` with the breakpoints and traps `sites` names lifted,
    /// planting each again over the code the write left (see
    /// [`BreakpointManager::write_under`]). With no site in the way the
    /// write goes straight to the target, running or not; otherwise the
    /// target is halted for it, since a site is planted and lifted through
    /// the backend. The sites are looked up again once it is halted: the
    /// stop that halts it may have planted, dropped or reloaded some.
    fn write_around_sites(
        &mut self,
        sites: impl Fn(&Session) -> (Vec<u32>, Vec<VirtAddr>),
        write: impl FnOnce(&Target) -> Result<()>,
    ) -> Result<()> {
        let (ids, traps) = sites(self);
        if ids.is_empty() && traps.is_empty() {
            return write(&self.target);
        }
        self.with_target_halted(|session| {
            let (ids, traps) = sites(session);
            for (lifted, &trap) in traps.iter().enumerate() {
                if let Err(error) =
                    lift_target_site(session.backend.as_mut(), &session.target, trap)
                {
                    let replanted = session.replant_traps(&traps[..lifted]);
                    return written_and_replanted(Err(error), replanted);
                }
            }
            let written = {
                let (mut breakpoints, backend, target) = session.breakpoint_sites();
                breakpoints.write_under(backend, target, &ids, || write(target))
            };
            let replanted = session.replant_traps(&traps);
            written_and_replanted(written, replanted)
        })
    }

    /// Plant the traps at `addresses` again after a write lifted them, each
    /// displacing the code now there. One that cannot be planted is dropped
    /// and named in the error: kept, it would be masked and lifted as if it
    /// were still there.
    fn replant_traps(&mut self, addresses: &[VirtAddr]) -> Result<()> {
        let mut failed = Vec::new();
        for &address in addresses {
            let mut original = vec![0u8; usize::from(self.target.arch().breakpoint_size())];
            if self
                .target
                .kernel_address_space()
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
                    let mut module_traps = self.module_traps.edit();
                    let mut bugcheck_trap = self.bugcheck_trap.edit();
                    let module_sites = module_traps.iter_mut().map(|trap| &mut trap.site);
                    for site in bugcheck_trap.iter_mut().chain(module_sites) {
                        if site.address == address {
                            site.original.clone_from(&original);
                        }
                    }
                }
                Err(error) => {
                    self.bugcheck_trap
                        .edit()
                        .take_if(|trap| trap.address == address);
                    self.module_traps
                        .edit()
                        .retain(|trap| trap.site.address != address);
                    failed.push(format!("{:#x} ({error})", address.0));
                }
            }
        }
        if failed.is_empty() {
            return Ok(());
        }
        Err(Error::Breakpoint(format!(
            "the debugger's trap at {} could not be planted again around the write",
            failed.join(", ")
        )))
    }

    /// Uninstall every breakpoint. Successful removals are forgotten; failed
    /// removals remain managed so callers can retry and must not resume the
    /// target as if cleanup had succeeded.
    pub fn remove_all_breakpoints(&mut self) -> Result<()> {
        let (mut breakpoints, backend, target) = self.breakpoint_sites();
        breakpoints.remove_all(backend, target)
    }

    /// Every debugger-owned site in guest RAM, the manager's breakpoints and
    /// the session's own traps: its guest-physical address and the bytes it
    /// displaced. A copy of guest RAM, such as a kernel dump, writes these in
    /// their place, so it holds the guest's code and not our breakpoints.
    pub fn displaced_frames(&self) -> Vec<(PhysAddr, Vec<u8>)> {
        if self.partition().is_some() {
            return Vec::new();
        }
        let mut frames = self.breakpoints.displaced_frames(&self.target);
        let memory = self.target.address_space(self.target.kernel_dtb());
        let module_sites = self.module_traps.iter().map(|trap| &trap.site);
        for trap in self.bugcheck_trap.iter().chain(module_sites) {
            if trap.original.is_empty() {
                continue;
            }
            if let Ok(Some(translation)) = memory.virt_to_phys(trap.address) {
                frames.push((translation.address, trap.original.clone()));
            }
        }
        frames
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
        if let Some(trap) = &*self.bugcheck_trap {
            lift_target_site(self.backend.as_mut(), &self.target, trap.address)?;
            *self.bugcheck_trap.edit() = None;
        }
        while let Some(trap) = self.module_traps.last() {
            lift_target_site(self.backend.as_mut(), &self.target, trap.site.address)?;
            self.module_traps.edit().pop();
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
                self.notices.push(Notice::warning(format!(
                    "failed to refresh module symbols after module change: {error}"
                )));
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

    pub fn reconcile_deferred_breakpoints(&mut self) {
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
            .edit()
            .reconcile_symbolic_after_module_refresh(self.backend.as_mut(), &self.target)
        {
            self.notices.push(Notice::warning(format!(
                "failed to reconcile breakpoints after module refresh: {error}"
            )));
        }
    }

    /// Take the latest module-symbol report for the REPL's existing summary.
    /// The report is private to the REPL's summary path.
    pub fn take_module_refresh_report(&mut self) -> Option<ModuleSymbolLoadReport> {
        self.module_refresh_report.take()
    }
}

/// The kernel function every user-mode image map runs, with the image's
/// name, the mapping process's ID and its `IMAGE_INFO` as its first three
/// arguments, as image-load notify routines get them.
pub const USER_IMAGE_TRAP: &str = "nt!PsCallImageNotifyRoutines";

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
