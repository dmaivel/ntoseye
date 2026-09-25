//! The breakpoint table's lifecycle: adding code breakpoints, enabling,
//! disabling, removing and renumbering them, and reinstalling their sites
//! after a stop.

use std::collections::{HashMap, HashSet};

use super::install::{BreakpointBackend, forget_site};
use super::spec::CodeSite;
use super::{Breakpoint, BreakpointConfig, BreakpointManager};
#[cfg(test)]
use super::{BreakpointScope, HardwareBreakpoint, install::BreakpointPatch};
use crate::backend::MemoryOps;
use crate::dbg_backend::{DebugBackend, HwBreakpointAccess};
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            one_shot_hits: HashSet::new(),
            next_id: 0,
        }
    }

    /// Test-only: register a breakpoint directly, bypassing backend
    /// installation. `hardware: Some(..)` makes a DR breakpoint; `None` a
    /// kernel int3 with a dummy displaced byte.
    #[cfg(test)]
    pub fn insert_for_test(
        &mut self,
        id: u32,
        address: VirtAddr,
        enabled: bool,
        hardware: Option<HardwareBreakpoint>,
    ) {
        let backend = match hardware {
            Some(_) => BreakpointBackend::Hardware,
            None => BreakpointBackend::Kernel {
                original: Some(BreakpointPatch::single(0x90)),
            },
        };
        self.breakpoints.insert(
            id,
            Breakpoint {
                id,
                address,
                enabled,
                symbol: None,
                spec: None,
                resolved: true,
                scope: BreakpointScope::Kernel,
                automatic_scope: false,
                thread: None,
                processor: None,
                condition: None,
                condition_expr: None,
                pass_count: 0,
                hit_count: 0,
                remaining_pass_count: 0,
                one_shot: false,
                action: None,
                temporary: false,
                hardware,
                backend,
            },
        );
    }

    pub fn add(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_code_configured(
            client,
            debugger,
            CodeSite::Address { address, symbol },
            BreakpointConfig {
                condition,
                ..BreakpointConfig::default()
            },
        )
    }

    pub fn add_configured(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.add_code_configured(
            client,
            debugger,
            CodeSite::Address { address, symbol },
            config,
        )
    }

    pub fn add_temporary_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
    ) -> Result<u32> {
        // Secure-kernel code is never patched: a run-to there (`p` over a
        // call, `gu`) takes a debug-register slot for the run instead.
        if debugger.is_secure_address(address) {
            let id = self.add_hardware_configured(
                client,
                debugger,
                address,
                HwBreakpointAccess::Execute,
                1,
                None,
                BreakpointConfig::default(),
            )?;
            if let Some(bp) = self.breakpoints.get_mut(&id) {
                bp.temporary = true;
            }
            return Ok(id);
        }
        self.add_code_configured(
            client,
            debugger,
            CodeSite::Temporary(address),
            BreakpointConfig::default(),
        )
    }

    pub(super) fn add_code_configured(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        site: CodeSite,
        config: BreakpointConfig,
    ) -> Result<u32> {
        let temporary = matches!(site, CodeSite::Temporary(_));
        let (address, symbol, spec) = match site {
            CodeSite::Address { address, symbol } => (Some(address), symbol, None),
            CodeSite::Spec { spec, address } => {
                (address, Some(spec.label().to_string()), Some(spec))
            }
            CodeSite::Temporary(address) => (Some(address), None, None),
        };
        let condition_expr = Self::configured_condition(&config)?;
        let automatic_scope = config.scope.is_none();
        let fallback_scope = config
            .scope
            .unwrap_or_else(|| Self::scope_for_current_context(debugger));
        let scope = if automatic_scope {
            address
                .map(|address| Self::scope_for_address(debugger, address, &fallback_scope))
                .unwrap_or(fallback_scope)
        } else {
            fallback_scope
        };
        Self::validate_scope_capability(client, debugger.arch(), address, &scope)?;

        let (address, resolved, backend) = match address {
            Some(address) => {
                self.ensure_site_available(address, false, None)?;
                Self::validate_breakpoint_target(debugger, address, &scope)?;
                let backend = Self::install_breakpoint(client, debugger, address, &scope)?;
                (address, true, backend)
            }
            None => (VirtAddr(0), false, BreakpointBackend::Deferred),
        };
        let pass_count = config.pass_count;
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints.insert(
            id,
            Breakpoint {
                id,
                address,
                enabled: true,
                symbol,
                spec,
                resolved,
                scope,
                automatic_scope,
                condition: config.condition,
                condition_expr,
                pass_count,
                hit_count: 0,
                remaining_pass_count: pass_count.saturating_sub(1),
                one_shot: config.one_shot,
                action: config.action,
                temporary,
                thread: config.thread,
                processor: config.processor,
                hardware: None,
                backend,
            },
        );
        Ok(id)
    }

    pub(super) fn ensure_site_available(
        &self,
        address: VirtAddr,
        hardware: bool,
        exclude_id: Option<u32>,
    ) -> Result<()> {
        if let Some(existing) = self.breakpoints.values().find(|bp| {
            Some(bp.id) != exclude_id
                && bp.resolved
                && bp.address == address
                && bp.hardware.is_some() == hardware
        }) {
            let kind = if hardware { "hardware" } else { "software" };
            return Err(Error::Breakpoint(format!(
                "{kind} breakpoint {} already owns address {:#x}",
                existing.id, address.0
            )));
        }
        Ok(())
    }

    pub fn remove(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        self.remove_if_uninstalled(id, |bp| Self::uninstall_breakpoint(client, debugger, bp))
    }

    pub(super) fn remove_ids(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        ids: impl IntoIterator<Item = u32>,
    ) -> Result<()> {
        self.remove_ids_if_uninstalled(ids, |bp| Self::uninstall_breakpoint(client, debugger, bp))
    }

    pub fn remove_all(&mut self, client: &mut dyn DebugBackend, debugger: &Target) -> Result<()> {
        let ids = self.managed_ids();
        self.remove_ids(client, debugger, ids)
    }

    fn remove_if_uninstalled(
        &mut self,
        id: u32,
        uninstall: impl FnOnce(&Breakpoint) -> Result<()>,
    ) -> Result<()> {
        let bp = self
            .breakpoints
            .get(&id)
            .cloned()
            .ok_or(Error::BPNotFound(id))?;

        if bp.enabled && bp.resolved {
            uninstall(&bp)?;
        }
        self.breakpoints.remove(&id);
        self.one_shot_hits.remove(&id);

        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }

        Ok(())
    }

    fn remove_ids_if_uninstalled(
        &mut self,
        ids: impl IntoIterator<Item = u32>,
        mut uninstall: impl FnMut(&Breakpoint) -> Result<()>,
    ) -> Result<()> {
        let mut failures = Vec::new();
        for id in ids {
            if let Err(error) = self.remove_if_uninstalled(id, |bp| uninstall(bp)) {
                failures.push(format!("#{id}: {error}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::Breakpoint(format!(
                "failed to uninstall breakpoints: {}",
                failures.join("; ")
            )))
        }
    }

    /// Forget a breakpoint whose site can no longer be restored (its address
    /// space is gone). The backend is told so it stops treating a hit at the
    /// stale address as ours.
    pub fn discard(&mut self, client: &mut dyn DebugBackend, id: u32) -> Result<Breakpoint> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        Self::forget_backend_site(client, &bp);
        self.one_shot_hits.remove(&id);
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        Ok(bp)
    }

    /// Rename a managed breakpoint without changing its installed backend
    /// site.  Breakpoint IDs are the user-facing handles, so one-shot state
    /// must move with the entry as well.
    pub fn renumber(&mut self, id: u32, new_id: u32) -> Result<()> {
        if id == new_id {
            if self.breakpoints.contains_key(&id) {
                return Ok(());
            }
            return Err(Error::BPNotFound(id));
        }
        if self.breakpoints.contains_key(&new_id) {
            return Err(Error::Breakpoint(format!(
                "breakpoint ID {new_id} is already in use"
            )));
        }
        let mut bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        bp.id = new_id;
        self.breakpoints.insert(new_id, bp);
        if self.one_shot_hits.remove(&id) {
            self.one_shot_hits.insert(new_id);
        }
        self.next_id = self.next_id.max(new_id.saturating_add(1));
        Ok(())
    }

    pub fn enable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let snapshot = self
            .breakpoints
            .get(&id)
            .cloned()
            .ok_or(Error::BPNotFound(id))?;
        if snapshot.enabled {
            return Ok(());
        }
        if snapshot.resolved {
            self.ensure_site_available(snapshot.address, snapshot.hardware.is_some(), Some(id))?;
            let backend = if matches!(
                &snapshot.backend,
                BreakpointBackend::Deferred | BreakpointBackend::Kernel { original: None }
            ) {
                Some(Self::install_breakpoint(
                    client,
                    debugger,
                    snapshot.address,
                    &snapshot.scope,
                )?)
            } else {
                Self::install_existing_breakpoint(client, debugger, &snapshot)?;
                None
            };
            if let Some(backend) = backend {
                self.breakpoints
                    .get_mut(&id)
                    .ok_or(Error::BPNotFound(id))?
                    .backend = backend;
            }
        }
        self.breakpoints
            .get_mut(&id)
            .ok_or(Error::BPNotFound(id))?
            .enabled = true;
        Ok(())
    }

    pub fn disable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }
        if bp.resolved {
            Self::uninstall_breakpoint(client, debugger, bp)?;
        }
        bp.enabled = false;
        Ok(())
    }

    pub fn disable_guest_memory_patch_in_address_space(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
        dtb: Dtb,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        match &bp.backend {
            BreakpointBackend::GuestMemoryPatch { original } => {
                let memory = debugger.address_space(dtb);
                memory.write_bytes(bp.address, original.as_slice())?;
                forget_site(debugger, &memory, bp.address);
                client.note_breakpoint_uninstalled(bp.address.0);
                bp.enabled = false;
                Ok(())
            }
            BreakpointBackend::Kernel { .. } => Err(Error::Breakpoint(
                "cannot address-space-disable a kernel breakpoint".into(),
            )),
            BreakpointBackend::Hardware => Err(Error::Breakpoint(
                "cannot address-space-disable a hardware breakpoint".into(),
            )),
            // Nothing was ever patched in any address space.
            BreakpointBackend::Deferred => {
                bp.enabled = false;
                Ok(())
            }
        }
    }

    pub fn managed_ids(&self) -> Vec<u32> {
        let mut ids = self.breakpoints.keys().copied().collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        let mut bps: Vec<_> = self
            .breakpoints
            .values()
            .filter(|bp| !self.one_shot_hits.contains(&bp.id))
            .collect();
        bps.sort_by_key(|bp| bp.id);
        bps
    }

    /// Find a managed breakpoint, including a one-shot hit retained until the
    /// next resume so the stop that reported it can expose its handle.
    pub fn get(&self, id: u32) -> Option<&Breakpoint> {
        self.breakpoints.get(&id)
    }

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints
            .values()
            .any(|bp| bp.enabled && bp.resolved)
    }

    pub fn refresh_enabled(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
    ) -> Result<()> {
        let mut enabled: Vec<_> = self
            .breakpoints
            .values()
            .filter(|bp| bp.enabled && bp.resolved && bp.hardware.is_none())
            .cloned()
            .collect();
        enabled.sort_by_key(|bp| bp.id);
        let dropped = client.sites_dropped_by_stop();

        for bp in enabled {
            // A target that owns its sites keeps them across a stop, except
            // the ones it dropped while reporting it; lifting and rewriting
            // the survivors would only churn its table. A site whose
            // displaced byte we never saw still goes through the reinstall
            // below, to pick that byte up now the page is resident.
            if client.target_manages_breakpoint_sites()
                && matches!(&bp.backend, BreakpointBackend::Kernel { original: Some(_) })
                && !dropped.contains(&bp.address.0)
            {
                continue;
            }
            // A restore that fails for any reason other than an absent page
            // leaves an `int3` at a site we can no longer account for, and
            // re-patching over it strands that byte: the saved original is
            // written back to whatever the address resolves to next, while the
            // old frame keeps the breakpoint. Surface the failure instead.
            let uninstalled = match Self::uninstall_breakpoint(client, debugger, &bp) {
                Ok(()) => true,
                // Nothing to restore: the page is gone, and the reinstall
                // below fails the same way and reports it.
                Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => false,
                Err(error) => return Err(error),
            };
            if uninstalled && matches!(&bp.backend, BreakpointBackend::Kernel { original: None }) {
                let backend = Self::install_breakpoint(client, debugger, bp.address, &bp.scope)?;
                self.breakpoints
                    .get_mut(&bp.id)
                    .ok_or(Error::BPNotFound(bp.id))?
                    .backend = backend;
            } else {
                Self::install_existing_breakpoint(client, debugger, &bp)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::{BreakpointManager, HardwareBreakpoint};
    use crate::dbg_backend::HwBreakpointAccess;
    use crate::error::Error;
    use crate::types::VirtAddr;

    #[test]
    fn failed_uninstall_keeps_breakpoint_managed_for_retry() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x1000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot: 0,
            }),
        );

        let result = manager.remove_if_uninstalled(7, |_| {
            Err(Error::Kd("injected hardware clear failure".into()))
        });
        assert!(result.is_err());
        assert_eq!(manager.list().len(), 1);
        assert_eq!(manager.list()[0].id, 7);
        assert!(manager.has_enabled_hardware_breakpoints());
    }

    #[test]
    fn renumber_moves_breakpoint_and_preserves_one_shot_state() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(2, VirtAddr(0x2000), true, None);
        manager.breakpoints.get_mut(&2).unwrap().one_shot = true;
        manager.mark_one_shot_hit(2).unwrap();

        manager.renumber(2, 7).unwrap();

        assert!(!manager.breakpoints.contains_key(&2));
        assert_eq!(manager.breakpoints.get(&7).unwrap().id, 7);
        assert_eq!(manager.one_shot_hit_ids(), vec![7]);
        assert!(manager.renumber(7, 7).is_ok());
        manager.insert_for_test(8, VirtAddr(0x8000), true, None);
        assert!(manager.renumber(7, 8).is_err());
        assert!(manager.breakpoints.contains_key(&7));
    }

    #[test]
    fn source_batch_rollback_removes_only_locations_added_by_the_batch() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(1, VirtAddr(0x1000), true, None);
        manager.insert_for_test(2, VirtAddr(0x2000), true, None);
        manager.insert_for_test(9, VirtAddr(0x9000), true, None);

        manager
            .remove_ids_if_uninstalled([2, 1], |_| Ok(()))
            .unwrap();

        let ids: Vec<_> = manager.list().into_iter().map(|bp| bp.id).collect();
        assert_eq!(ids, vec![9]);
    }

    #[test]
    fn source_batch_rollback_reports_failed_uninstall_and_keeps_it_managed() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(1, VirtAddr(0x1000), true, None);
        manager.insert_for_test(2, VirtAddr(0x2000), true, None);
        manager.insert_for_test(9, VirtAddr(0x9000), true, None);

        let error = manager
            .remove_ids_if_uninstalled([2, 1], |bp| {
                if bp.id == 2 {
                    Err(Error::Kd("injected rollback failure".into()))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();

        assert!(error.to_string().contains("#2"));
        assert!(error.to_string().contains("injected rollback failure"));
        let ids: Vec<_> = manager.list().into_iter().map(|bp| bp.id).collect();
        assert_eq!(ids, vec![2, 9]);
    }

    #[test]
    fn physical_breakpoint_sites_reject_same_kind_collisions() {
        let mut manager = BreakpointManager::new();
        let address = VirtAddr(0x4000);
        manager.insert_for_test(2, address, false, None);

        let error = manager
            .ensure_site_available(address, false, None)
            .expect_err("disabled breakpoints still own their physical site");
        assert!(error.to_string().contains("breakpoint 2 already owns"));
        assert!(manager.ensure_site_available(address, true, None).is_ok());
    }
}
