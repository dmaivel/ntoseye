//! Deferred symbol and source breakpoints: adding them, resolving them as
//! modules load and unload, and keeping their identity across a target
//! reload.

use super::install::BreakpointBackend;
use super::spec::CodeSite;
use super::{Breakpoint, BreakpointConfig, BreakpointManager, BreakpointScope, BreakpointSpec};
use crate::dbg_backend::DebugBackend;
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

impl BreakpointManager {
    pub fn add_symbolic(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        symbol: String,
        config: BreakpointConfig,
    ) -> Result<u32> {
        let spec = BreakpointSpec::Symbol {
            name: symbol.clone(),
            skip_prologue: config.skip_prologue,
        };
        let dtb = Self::resolution_dtb(debugger, config.scope.as_ref());
        let mut address = spec.resolve(debugger, dtb)?;
        if address.is_none() {
            let module = symbol.split_once('!').map(|(module, _)| module.trim());
            if Self::load_scope_symbols(debugger, config.scope.as_ref(), module)? {
                address = spec.resolve(debugger, dtb)?;
            }
        }
        self.add_code_configured(client, debugger, CodeSite::Spec { spec, address }, config)
    }

    /// Add one deferred identity per currently known address for `file:line`.
    /// If no module currently supplies source mappings, retain one unresolved
    /// identity (index zero) for a later symbol/module refresh. The batch is
    /// transactional: if any location fails, every location installed by this
    /// call is removed before the error is returned.
    pub fn add_source(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        source: String,
        config: BreakpointConfig,
    ) -> Result<Vec<u32>> {
        let Some(first_spec) = BreakpointSpec::source(&source, 0) else {
            return Err(Error::InvalidArgument(format!(
                "invalid source breakpoint: {source}"
            )));
        };
        let dtb = Self::resolution_dtb(debugger, config.scope.as_ref());
        let source_address_count = |first_spec: &BreakpointSpec| match first_spec {
            BreakpointSpec::Source { file, line, .. } => {
                debugger.symbols.source_addresses(dtb, file, *line).len()
            }
            BreakpointSpec::Symbol { .. } => unreachable!(),
        };
        let mut address_count = source_address_count(&first_spec);
        // A file:line can live in any of the process's modules, so a miss
        // loads them all (what `.process /p` would have done).
        if address_count == 0 && Self::load_scope_symbols(debugger, config.scope.as_ref(), None)? {
            address_count = source_address_count(&first_spec);
        }
        let count = address_count.max(1);
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let result = (|| {
                let spec = BreakpointSpec::source(&source, index).ok_or_else(|| {
                    Error::InvalidArgument(format!("invalid source breakpoint: {source}"))
                })?;
                let address = spec.resolve(debugger, dtb)?;
                self.add_code_configured(
                    client,
                    debugger,
                    CodeSite::Spec { spec, address },
                    config.clone(),
                )
            })();

            match result {
                Ok(id) => ids.push(id),
                Err(error) => {
                    if let Err(rollback_error) =
                        self.remove_ids(client, debugger, ids.iter().rev().copied())
                    {
                        return Err(Error::Breakpoint(format!(
                            "failed to add source breakpoint '{source}': {error}; rollback incomplete: {rollback_error}"
                        )));
                    }
                    return Err(error);
                }
            }
        }
        Ok(ids)
    }

    fn resolution_dtb(debugger: &Target, scope: Option<&BreakpointScope>) -> Dtb {
        match scope {
            Some(BreakpointScope::Process { dtb, .. }) => *dtb,
            Some(BreakpointScope::Kernel) => debugger.kernel_dtb(),
            None => debugger.current_dtb(),
        }
    }

    /// A process-scoped specification that did not resolve: read that
    /// process's loader list and load the named module's symbols (or all of
    /// them for a source line), so `bu /p <pid> user32!X` works without a
    /// prior `.process /p`. Returns whether anything new was loaded. Kernel
    /// and unscoped specifications resolve against what is loaded; a miss
    /// there really is deferred until the module appears.
    fn load_scope_symbols(
        debugger: &Target,
        scope: Option<&BreakpointScope>,
        module_short: Option<&str>,
    ) -> Result<bool> {
        let Some(BreakpointScope::Process { pid, dtb, .. }) = scope else {
            return Ok(false);
        };
        debugger.load_process_module_symbols(*pid, *dtb, module_short)
    }

    /// Keep symbolic code breakpoints across a target rebuild while dropping
    /// every backend installation and all target-specific numeric/watch points.
    pub fn prepare_target_reload(&mut self, client: &mut dyn DebugBackend) -> usize {
        self.clear_hardware_slots(client);
        let before = self.breakpoints.len();
        let fired_one_shots = std::mem::take(&mut self.one_shot_hits);
        self.breakpoints.retain(|id, bp| {
            !fired_one_shots.contains(id) && bp.hardware.is_none() && bp.spec.is_some()
        });
        for bp in self.breakpoints.values_mut() {
            bp.resolved = false;
            bp.backend = BreakpointBackend::Deferred;
        }
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        before - self.breakpoints.len()
    }

    /// Resolve every symbolic breakpoint against the current symbol store.
    /// IDs, counters, conditions, actions, and enabled state survive address
    /// changes. Unavailable symbols remain deferred without backend state.
    fn expand_source_specs(&mut self, debugger: &Target) {
        let roots: Vec<Breakpoint> = self
            .breakpoints
            .values()
            .filter(|bp| {
                matches!(
                    bp.spec,
                    Some(BreakpointSpec::Source {
                        address_index: 0,
                        ..
                    })
                )
            })
            .cloned()
            .collect();
        for root in roots {
            let Some(BreakpointSpec::Source {
                raw, file, line, ..
            }) = root.spec.as_ref()
            else {
                continue;
            };
            let dtb = Self::resolution_dtb(debugger, Some(&root.scope));
            let count = debugger.symbols.source_addresses(dtb, file, *line).len();
            for address_index in 1..count {
                let already_exists = self.breakpoints.values().any(|bp| {
                    matches!(
                        bp.spec.as_ref(),
                        Some(BreakpointSpec::Source {
                            raw: other,
                            address_index: other_index,
                            ..
                        }) if other == raw && *other_index == address_index
                    )
                });
                if already_exists {
                    continue;
                }
                let id = self.next_id;
                self.next_id += 1;
                let mut bp = root.clone();
                bp.id = id;
                bp.address = VirtAddr(0);
                bp.spec = BreakpointSpec::source(raw, address_index);
                bp.resolved = false;
                bp.backend = BreakpointBackend::Deferred;
                self.breakpoints.insert(id, bp);
            }
        }
    }

    fn defer_symbolic_sites_if(
        &mut self,
        client: &mut dyn DebugBackend,
        mut site_is_unloaded: impl FnMut(&Breakpoint) -> bool,
    ) -> usize {
        let ids = self
            .breakpoints
            .values()
            .filter(|bp| {
                bp.resolved && bp.spec.is_some() && bp.hardware.is_none() && site_is_unloaded(bp)
            })
            .map(|bp| bp.id)
            .collect::<Vec<_>>();

        for id in &ids {
            let bp = self
                .breakpoints
                .get_mut(id)
                .expect("collected breakpoint exists");
            // The module mapping is already gone. Do not send a removal request
            // for its stale address: it may be unmapped or reused by now.
            Self::forget_backend_site(client, bp);
            bp.resolved = false;
            bp.backend = BreakpointBackend::Deferred;
        }
        ids.len()
    }

    /// Reconcile symbolic breakpoints after the live module set changes.
    ///
    /// Sites whose owning module disappeared become deferred without touching
    /// their stale target address. Newly available specifications are then
    /// resolved and installed normally.
    pub fn reconcile_symbolic_after_module_refresh(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
    ) -> Result<usize> {
        self.defer_symbolic_sites_if(client, |bp| {
            let dtb = Self::resolution_dtb(debugger, Some(&bp.scope));
            debugger
                .symbols
                .find_module_for_address(dtb, bp.address)
                .is_none()
        });
        self.resolve_symbolic(client, debugger)
    }

    pub fn resolve_symbolic(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
    ) -> Result<usize> {
        self.expand_source_specs(debugger);
        let mut ids: Vec<u32> = self
            .breakpoints
            .values()
            .filter(|bp| bp.spec.is_some() && bp.hardware.is_none())
            .map(|bp| bp.id)
            .collect();
        ids.sort_unstable();

        let mut resolved_count = 0;
        // One unarmable site must not stop the others: a driver's `INIT`
        // section is gone once `DriverEntry` returns, and the target refuses
        // a breakpoint there. Failures are collected and reported after every
        // other specification has had its chance.
        let mut failures: Vec<String> = Vec::new();
        for id in ids {
            let snapshot = self
                .breakpoints
                .get(&id)
                .cloned()
                .ok_or(Error::BPNotFound(id))?;
            let spec = snapshot.spec.as_ref().ok_or_else(|| {
                Error::Breakpoint(format!("breakpoint {id} lost its specification"))
            })?;
            let dtb = Self::resolution_dtb(debugger, Some(&snapshot.scope));
            let resolved = spec.resolve(debugger, dtb)?;
            let scope = resolved
                .filter(|_| snapshot.automatic_scope)
                .map(|address| Self::scope_for_address(debugger, address, &snapshot.scope))
                .unwrap_or_else(|| snapshot.scope.clone());

            if snapshot.resolved && resolved == Some(snapshot.address) && scope == snapshot.scope {
                resolved_count += 1;
                continue;
            }

            if let Some(address) = resolved
                && let Err(error) =
                    Self::validate_scope_capability(client, debugger.arch(), resolved, &scope)
                        .and_then(|()| Self::validate_breakpoint_target(debugger, address, &scope))
                        .and_then(|()| self.ensure_site_available(address, false, Some(id)))
            {
                failures.push(format!("breakpoint {id}: {error}"));
                continue;
            }

            if snapshot.resolved
                && snapshot.enabled
                && let Err(error) = Self::uninstall_breakpoint(client, debugger, &snapshot)
            {
                failures.push(format!("breakpoint {id}: {error}"));
                continue;
            }

            let backend = match resolved {
                Some(address) if snapshot.enabled => {
                    match Self::install_breakpoint(client, debugger, address, &scope) {
                        Ok(backend) => backend,
                        Err(install_error) => {
                            if snapshot.resolved
                                && let Err(rollback_error) =
                                    Self::install_existing_breakpoint(client, debugger, &snapshot)
                            {
                                failures.push(format!(
                                    "failed to move breakpoint {id}: {install_error}; restoring its previous installation also failed: {rollback_error}"
                                ));
                                continue;
                            }
                            failures.push(format!("breakpoint {id}: {install_error}"));
                            continue;
                        }
                    }
                }
                _ => BreakpointBackend::Deferred,
            };

            let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
            match resolved {
                Some(address) => {
                    bp.address = address;
                    bp.resolved = true;
                    bp.scope = scope;
                    bp.backend = backend;
                    bp.symbol = Some(spec.label().to_string());
                    resolved_count += 1;
                }
                None => {
                    bp.resolved = false;
                    bp.backend = BreakpointBackend::Deferred;
                }
            }
        }
        if !failures.is_empty() {
            return Err(Error::Breakpoint(failures.join("; ")));
        }
        Ok(resolved_count)
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::install::BreakpointBackend;
    use crate::breakpoints::test_backend::SlotRecorder;
    use crate::breakpoints::{BreakpointHitResult, BreakpointManager, BreakpointSpec};
    use crate::session::session_over_memory;
    use crate::types::{Arch, VirtAddr};

    #[test]
    fn one_unarmable_site_does_not_block_the_others() {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_module_for_test(
            1,
            Vec::new(),
            &[("Refused", 0x10), ("Allowed", 0x20)],
        );
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x1000,
            "driver.c",
            &[],
        );

        let mut manager = BreakpointManager::new();
        for (id, name) in [(0u32, "driver!Refused"), (1, "driver!Allowed")] {
            manager.insert_for_test(id, VirtAddr(0), true, None);
            let bp = manager.breakpoints.get_mut(&id).unwrap();
            bp.spec = Some(BreakpointSpec::Symbol {
                name: name.to_string(),
                skip_prologue: false,
            });
            bp.resolved = false;
            bp.backend = BreakpointBackend::Deferred;
        }

        let mut client = SlotRecorder::refusing(0x1010);
        let error = manager
            .resolve_symbolic(&mut client, &session.target)
            .expect_err("the refused site is reported");
        assert!(
            error.to_string().contains("breakpoint 0"),
            "failure names the breakpoint: {error}"
        );
        assert!(!manager.breakpoints[&0].resolved);
        let allowed = &manager.breakpoints[&1];
        assert!(
            allowed.resolved && allowed.address == VirtAddr(0x1020),
            "the armable site still resolved: {allowed:?}"
        );
    }

    #[test]
    fn target_reload_keeps_symbolic_identity_deferred_and_drops_numeric_points() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(1, VirtAddr(0x1000), true, None);
        manager.insert_for_test(7, VirtAddr(0x2000), true, None);
        {
            let symbolic = manager.breakpoints.get_mut(&7).unwrap();
            symbolic.symbol = Some("driver!Entry".into());
            symbolic.spec = Some(BreakpointSpec::Symbol {
                name: "driver!Entry".into(),
                skip_prologue: false,
            });
        }
        let mut backend = SlotRecorder::new();
        assert_eq!(manager.prepare_target_reload(&mut backend), 1);
        let bp = manager.list()[0];
        assert_eq!(bp.id, 7);
        assert!(bp.deferred());
        assert_eq!(bp.address, VirtAddr(0x2000));
        assert!(matches!(bp.backend, BreakpointBackend::Deferred));
    }

    #[test]
    fn unloaded_symbolic_site_becomes_deferred_without_dropping_identity() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(3, VirtAddr(0x3000), true, None);
        manager.insert_for_test(4, VirtAddr(0x4000), true, None);
        manager.breakpoints.get_mut(&3).unwrap().spec = Some(BreakpointSpec::Source {
            raw: "probe.c:35".into(),
            file: "probe.c".into(),
            line: 35,
            address_index: 0,
        });

        assert_eq!(
            manager.defer_symbolic_sites_if(&mut SlotRecorder::new(), |bp| bp.id == 3),
            1
        );

        let deferred = manager.breakpoints.get(&3).unwrap();
        assert!(deferred.enabled);
        assert!(deferred.deferred());
        assert_eq!(deferred.address, VirtAddr(0x3000));
        assert!(matches!(deferred.backend, BreakpointBackend::Deferred));
        assert!(manager.breakpoints.get(&4).unwrap().resolved);
        assert!(matches!(
            manager.check_breakpoint_hit(0x3000, 0, Arch::Amd64),
            BreakpointHitResult::NotBreakpoint
        ));
    }
}
