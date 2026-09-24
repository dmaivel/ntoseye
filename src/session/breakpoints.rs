//! Breakpoint and watchpoint management, deferred-breakpoint
//! reconciliation, and the automatic `nt!KeBugCheckEx` trap.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::dbg_backend::{BugcheckInfo, DebugCapability, WatchpointAccess};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::breakpoints::{Breakpoint, BreakpointConfig, BreakpointScope, ThreadScope};
use crate::guest::ModuleSymbolLoadReport;
use crate::session::Session;
use crate::types::{Arch, VirtAddr};

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

    /// Set one symbol-identity breakpoint per symbol matching `pattern`
    /// (`bm`): `*`/`?` globs, optionally `module!`-qualified; at most `limit`
    /// matches. Returns the ids created, and the count of matches that
    /// failed to install (already reported through `errors`).
    pub fn add_pattern_breakpoints(
        &mut self,
        pattern: &str,
        config: BreakpointConfig,
        limit: usize,
    ) -> Result<(Vec<u32>, Vec<Error>)> {
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
                Err(error) => errors.push(error),
            }
        }
        Ok((ids, errors))
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

    /// Arm an automatic breakpoint on `nt!KeBugCheckEx` when the backend
    /// cannot recognize a bugcheck on its own.
    ///
    /// KD learns of a crash from the target itself; a hypervisor stub never
    /// does, so the crash is only observable by stopping the guest as it
    /// enters the bugcheck. Armed at attach, where the operator can see it
    /// reported, and retried on every resume: the site needs kernel symbols,
    /// which can arrive late and move across a reboot.
    pub(super) fn arm_bugcheck_trap(&mut self) {
        let capabilities = self.backend.capabilities();
        let supports = |capability| {
            capabilities
                .iter()
                .any(|entry| entry.capability == capability && entry.supported)
        };
        // A target that reports its own bugchecks needs no trap, and one that
        // cannot hold a breakpoint cannot be given one.
        if self.bugcheck_trap.is_some()
            || supports(DebugCapability::BugcheckDetection)
            || !supports(DebugCapability::KernelBreakpoints)
        {
            return;
        }
        let Some(guest) = self.target.guest.as_ref() else {
            return;
        };
        let kernel_dtb = guest.ntoskrnl.dtb();
        let Ok(Some(address)) = self
            .target
            .symbols
            .find_symbol_across_modules(kernel_dtb, "nt!KeBugCheckEx")
        else {
            return;
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

        match self.backend.set_breakpoint(address.0) {
            Ok(()) => {
                self.bugcheck_trap = Some(address);
                self.bugcheck_trap_original = original;
                self.notices.push(format!(
                    "armed a bugcheck trap at nt!KeBugCheckEx ({:#x}); the {} backend cannot detect a bugcheck by itself",
                    address.0,
                    self.backend.name()
                ));
            }
            Err(error) => self.notices.push(format!(
                "failed to arm a bugcheck trap at nt!KeBugCheckEx: {error}"
            )),
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

    /// Put the bugcheck trap's displaced instruction back into a read that
    /// covers it. The trap is not one of the manager's breakpoints, so the
    /// manager cannot mask it, and without this `u nt!KeBugCheckEx` shows the
    /// debugger's own trap instead of the guest's code.
    pub(super) fn mask_bugcheck_trap(&self, start: VirtAddr, buf: &mut [u8]) {
        let Some(address) = self.bugcheck_trap else {
            return;
        };
        if self.bugcheck_trap_original.is_empty() || address.0 < start.0 {
            return;
        }
        let offset = (address.0 - start.0) as usize;
        let end = offset + self.bugcheck_trap_original.len();
        if end <= buf.len() {
            buf[offset..end].copy_from_slice(&self.bugcheck_trap_original);
        }
    }

    /// Uninstall every breakpoint. Successful removals are forgotten; failed
    /// removals remain managed so callers can retry and must not resume the
    /// target as if cleanup had succeeded.
    pub fn remove_all_breakpoints(&mut self) -> Result<()> {
        self.breakpoints
            .remove_all(self.backend.as_mut(), &self.target)
    }

    /// Whether any debugger-owned site is installed in the guest. The
    /// bugcheck trap is not one of the manager's breakpoints, so a caller
    /// asking whether there is anything to restore has to ask for both.
    pub fn has_installed_sites(&self) -> bool {
        !self.breakpoints.list().is_empty() || self.bugcheck_trap.is_some()
    }

    /// Take the automatic bugcheck trap back out of the guest.
    ///
    /// Nothing else does: it is not one of the manager's breakpoints, and a
    /// GDB stub leaves the `int3` it wrote in guest memory when the
    /// connection closes. Left behind, it is executed by the next thread to
    /// reach `nt!KeBugCheckEx` with no debugger attached.
    pub fn disarm_bugcheck_trap(&mut self) -> Result<()> {
        let Some(address) = self.bugcheck_trap else {
            return Ok(());
        };
        self.backend.remove_breakpoint(address.0)?;
        self.bugcheck_trap = None;
        self.bugcheck_trap_original.clear();
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
