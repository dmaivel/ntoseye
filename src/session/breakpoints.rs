//! Breakpoint and watchpoint management, deferred-breakpoint
//! reconciliation, and the automatic `nt!KeBugCheckEx` trap.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::breakpoints::{
    Breakpoint, BreakpointConfig, BreakpointScope, ThreadScope, lift_target_site, plant_target_site,
};
use crate::dbg_backend::{BugcheckInfo, DebugCapability, WatchpointAccess};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ModuleSymbolLoadReport;
use crate::session::{Session, TrapSite};
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
    /// trap ([`Self::arm_bugcheck_trap`]) and the module-load trap
    /// ([`Self::arm_load_trap`]). Armed at attach, where the operator can see
    /// them reported, and retried on every resume: the sites need kernel
    /// symbols, which can arrive late and move across a reboot.
    pub fn arm_traps(&mut self) {
        self.arm_bugcheck_trap();
        self.arm_load_trap();
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

    /// Arm an automatic breakpoint on `nt!DbgLoadImageSymbols` when the
    /// backend reports no module loads on its own.
    ///
    /// The kernel calls it for every kernel image it maps, with the image
    /// listed in `PsLoadedModuleList` and before its entry point runs, whether
    /// or not kernel debugging is enabled; it is where KD's load notification
    /// comes from. A hit refreshes the module list, arms deferred breakpoints
    /// in the new image, and applies the `sx* ld` filters (see
    /// [`Self::classify_stop_event`]).
    fn arm_load_trap(&mut self) {
        if self.load_trap.is_some() || self.backend_supports(DebugCapability::ModuleLoadEvents) {
            return;
        }
        self.load_trap = self.plant_trap(
            "nt!DbgLoadImageSymbols",
            "a module-load trap",
            "reports no module loads by itself",
        );
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
    /// Returns the stop-point id.
    pub fn add_watchpoint(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.breakpoints.add_hardware_configured(
            self.backend.as_mut(),
            &self.target,
            addr,
            access.into(),
            len,
            symbol,
            config,
        )
    }

    /// Remove a breakpoint by id.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .remove(self.backend.as_mut(), &self.target, id)
    }

    /// Re-arm a disabled breakpoint (re-patch its `int3`).
    pub fn enable_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .enable(self.backend.as_mut(), &self.target, id)
    }

    /// Disable a breakpoint (restore the original byte) without forgetting it,
    /// so it can be re-enabled later.
    pub fn disable_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .disable(self.backend.as_mut(), &self.target, id)
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.list()
    }

    /// Return one breakpoint by id.
    pub fn breakpoint(&self, id: u32) -> Option<&Breakpoint> {
        self.breakpoints.list().into_iter().find(|bp| bp.id == id)
    }

    /// Put the traps' displaced instructions back into a read that covers
    /// them. The traps are not the manager's breakpoints, so the manager
    /// cannot mask them, and without this `u nt!KeBugCheckEx` shows the
    /// debugger's own trap instead of the guest's code.
    pub fn mask_traps(&self, start: VirtAddr, buf: &mut [u8]) {
        for trap in [&self.bugcheck_trap, &self.load_trap].into_iter().flatten() {
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
        self.breakpoints
            .remove_all(self.backend.as_mut(), &self.target)
    }

    /// Whether any debugger-owned site is installed in the guest. The traps
    /// are not the manager's breakpoints, so a caller asking whether there is
    /// anything to restore has to ask for them too.
    pub fn has_installed_sites(&self) -> bool {
        !self.breakpoints.list().is_empty()
            || self.bugcheck_trap.is_some()
            || self.load_trap.is_some()
    }

    /// Take the automatic bugcheck and module-load traps back out of the
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
        if let Some(trap) = &self.load_trap {
            lift_target_site(self.backend.as_mut(), &self.target, trap.address)?;
            self.load_trap = None;
            self.load_trap_interrupted = None;
        }
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
