//! Building a target over guest memory, rebuilding it after a reboot, and
//! the kernel discovery metadata (debugger data, startup identity) it keeps.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{ReloadReport, StartupMessage, Target};
use crate::{
    backend::MemoryOps,
    debugger_data::{
        DebuggerDataBlock, DebuggerDataCandidate, MetadataSource, locate_debugger_data_block,
    },
    dmp::DmpInfo,
    error::{Error, Result},
    guest::{Guest, ModuleInfo, SessionSpace},
    memory::DTB_IDENTITY,
    phys::PhysMem,
    symbols::SymbolStore,
    types::{Arch, Dtb, KernelLocation, VirtAddr},
};

/// Kernel discovery found nothing in a live target's memory. Name what was
/// searched: the two causes look identical otherwise, and the numbers tell
/// them apart. A host mapping the size of the guest's configured RAM means
/// the memory is right and the guest simply has not reached its kernel; any
/// other size means the mapped region is not the guest's RAM.
///
/// A target-mediated source reports no size, so it keeps the bare error.
fn no_kernel_in_live_memory(phys: &PhysMem) -> Error {
    let size = phys.ram_size();
    if size == 0 {
        return Error::NtoskrnlNotFound;
    }
    Error::DebugInfo(format!(
        "no Windows kernel in the {} MiB of guest memory mapped at guest-physical {:#x} ({}).\n\
         Either the guest has not reached its kernel yet, or that mapping is not its RAM.",
        size / (1024 * 1024),
        phys.ram_base(),
        phys.host_mapping()
            .unwrap_or_else(|| "unknown mapping".into())
    ))
}

impl Target {
    pub fn new() -> Result<Self> {
        Self::with_phys(Arc::new(PhysMem::live()?))
    }

    pub fn with_phys(phys: Arc<PhysMem>) -> Result<Self> {
        let symbols = Arc::new(SymbolStore::new());
        let mut notices = Vec::new();
        let guest = if let Some(info) = phys.dmp_info() {
            let dtb = if info.is_triage {
                DTB_IDENTITY
            } else {
                info.directory_table_base
            };
            match Guest::new_with_dtb(phys.clone(), symbols.clone(), dtb) {
                Ok(g) => Some(g),
                Err(Error::NtoskrnlNotFound) if info.is_triage => None,
                // Triage degradation must survive any discovery failure
                // (e.g. a symbol download error while offline), not just a
                // missing kernel; identity-mapped access still works.
                Err(e) if info.is_triage => {
                    notices.push(format!(
                        "kernel discovery failed ({e}); continuing without kernel context"
                    ));
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            match Guest::new(phys.clone(), symbols.clone()) {
                Ok(guest) => Some(guest),
                Err(Error::NtoskrnlNotFound) => return Err(no_kernel_in_live_memory(&phys)),
                Err(e) => return Err(e),
            }
        };

        // Pre-compute the triage module list once for both symbol loading and
        // the cached fallback returned by kernel_modules().
        let triage_modules: Option<Vec<ModuleInfo>> = phys
            .dmp_info()
            .filter(|info| info.is_triage && !info.triage_drivers.is_empty())
            .map(|info| {
                info.triage_drivers
                    .iter()
                    .map(|d| d.to_module_info())
                    .collect()
            });

        if let Some(ref guest) = guest {
            let _ = guest.load_all_kernel_module_symbols(&phys, &symbols);
        } else if let Some(ref modules) = triage_modules {
            let arch = phys
                .dmp_info()
                .and_then(DmpInfo::arch)
                .unwrap_or(Arch::Amd64);
            let _ = Guest::load_module_symbols(
                &phys,
                &symbols,
                modules.clone(),
                DTB_IDENTITY,
                SessionSpace::Load,
                arch,
            );
        }

        let triage_modules_cache = triage_modules;

        Ok(Self {
            phys,
            symbols,
            guest,
            debugger_data: None,
            process: None,
            secure_root: None,
            effmach: None,
            triage_modules_cache,
            context_dtb_override: None,
            registers: None,
            selected_frame: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
            last_exception_code: None,
            interrupt: Arc::new(AtomicBool::new(false)),
            notices,
            generation: Arc::new(AtomicU64::new(0)),
            site_journal: None,
        })
    }

    /// Build a target from KD-provided kernel metadata and KD-backed physical
    /// memory. This bypasses host RAM scanning, which is unavailable for remote
    /// or bare-metal targets.
    pub fn with_remote_phys(
        phys: Arc<PhysMem>,
        kernel_dtb: Dtb,
        kernel_base: VirtAddr,
        arch: Arch,
    ) -> Result<Self> {
        let symbols = Arc::new(SymbolStore::new());
        let guest = Guest::at(
            phys.clone(),
            symbols.clone(),
            KernelLocation {
                dtb: kernel_dtb,
                base: kernel_base,
                arch,
            },
        )?;
        let _ = guest.load_all_kernel_module_symbols(&phys, &symbols);

        Ok(Self {
            phys,
            symbols,
            guest: Some(guest),
            debugger_data: None,
            process: None,
            secure_root: None,
            effmach: None,
            triage_modules_cache: None,
            context_dtb_override: None,
            registers: None,
            selected_frame: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
            last_exception_code: None,
            interrupt: Arc::new(AtomicBool::new(false)),
            notices: Vec::new(),
            generation: Arc::new(AtomicU64::new(0)),
            site_journal: None,
        })
    }

    /// How many times the guest has been rebuilt; see the field.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The rebuild counter itself, for a host that checks handle staleness
    /// from another thread without a trip to the session.
    pub fn generation_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }

    pub fn debugger_data(&self) -> Option<&DebuggerDataBlock> {
        self.debugger_data.as_ref()
    }

    /// Refresh the validated kernel debugger-data snapshot from transport,
    /// symbols, or dump metadata, in that order.
    pub fn refresh_debugger_data(&mut self, transport_hint: Option<DebuggerDataCandidate>) {
        let mut candidates = Vec::with_capacity(4);
        if let Some(candidate) = transport_hint {
            candidates.push(candidate);
        }
        if let Some(guest) = &self.guest {
            for symbol in ["KdDebuggerDataBlock", "KdDebuggerDataListHead"] {
                if let Ok(Some(address)) = self
                    .symbols
                    .find_symbol_across_modules(guest.ntoskrnl.dtb(), &format!("nt!{symbol}"))
                {
                    candidates.push(DebuggerDataCandidate {
                        address,
                        source: MetadataSource::KernelSymbol,
                    });
                }
            }
        }
        if let Some(address) = self
            .phys
            .dmp_info()
            .and_then(|info| info.debugger_data_block)
        {
            candidates.push(DebuggerDataCandidate {
                address: VirtAddr(address),
                source: MetadataSource::DumpHeader,
            });
        }

        let expected_kernel_base = self.kernel_base();
        let debugger_data = {
            let memory = self.context_memory();
            locate_debugger_data_block(&memory, candidates, expected_kernel_base)
        };
        self.debugger_data = debugger_data;
    }

    /// Rebuild the guest after a reboot: at `location` when the transport
    /// knows it, else by scanning RAM (seeded with `kernel_base_hint`).
    pub fn reload_guest(
        &mut self,
        location: Option<KernelLocation>,
        kernel_base_hint: Option<VirtAddr>,
    ) -> Result<ReloadReport> {
        self.debugger_data = None;
        let previous_base_address = self
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.base_address)
            .unwrap_or(VirtAddr(0));
        let previous_dtb = self.guest.as_ref().map(|g| g.ntoskrnl.dtb());
        let previous_secure_dtb = self
            .guest
            .as_ref()
            .and_then(|g| g.cached_secure_kernel())
            .map(|s| s.image.dtb());
        let (phys, symbols) = (self.phys.clone(), self.symbols.clone());
        let guest = match location {
            Some(location) => Guest::at(phys, symbols, location)?,
            None => Guest::new_with_kernel_base_hint(phys, symbols, kernel_base_hint)?,
        };
        let new_dtb = guest.ntoskrnl.dtb();

        if let Some(prev_dtb) = previous_dtb {
            self.symbols.clear_modules_for_dtb(prev_dtb);
        }
        if let Some(prev_dtb) = previous_secure_dtb {
            self.symbols.clear_modules_for_dtb(prev_dtb);
        }
        self.symbols.clear_modules_for_dtb(new_dtb);

        let (symbol_report, symbol_error) =
            match guest.load_all_kernel_module_symbols(&self.phys, &self.symbols) {
                Ok(report) => (Some(report), None),
                Err(e) => (None, Some(e.to_string())),
            };

        self.guest = Some(guest);
        self.triage_modules_cache = None;
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.detach();
        self.clear_context_dtb_override();
        self.registers = None;
        self.clear_current_windows_thread_context();
        let startup = self.startup_message_data().ok();

        Ok(ReloadReport {
            previous_base_address,
            startup,
            symbol_report,
            symbol_error,
        })
    }

    pub fn current_kernel_mapping_is_valid(&self) -> bool {
        // Triage dumps often lack the ntoskrnl base page, so the MZ check
        // below would fail on a perfectly coherent snapshot.
        if self.phys.dmp_info().is_some_and(|i| i.is_triage) {
            return true;
        }
        let Some(ref guest) = self.guest else {
            return false;
        };
        let memory = guest.ntoskrnl.memory();
        let mut signature = [0u8; 2];
        memory
            .read_bytes(guest.ntoskrnl.base_address, &mut signature)
            .is_ok_and(|()| signature == *b"MZ")
    }

    pub fn rediscovered_kernel_identity_changed(&self) -> Result<bool> {
        let current_guest = self.guest()?;
        let guest = Guest::new(self.phys.clone(), self.symbols.clone())?;
        Ok(
            guest.ntoskrnl.base_address != current_guest.ntoskrnl.base_address
                || guest.ntoskrnl.dtb() != current_guest.ntoskrnl.dtb(),
        )
    }

    pub fn startup_message_data(&mut self) -> Result<StartupMessage> {
        // Dumps may not capture these symbols' memory, so they degrade to
        // zeroed fields; live sessions propagate the underlying error.
        let degraded = self.phys.dmp_info().is_some();
        let guest = self.guest()?;
        let build_number: u16 = match guest
            .ntoskrnl
            .symbol("NtBuildNumber")
            .and_then(|s| s.read())
        {
            Ok(v) => v,
            Err(_) if degraded => 0,
            Err(e) => return Err(e),
        };
        let base_address = guest.ntoskrnl.base_address;
        let loaded_module_list = match guest
            .ntoskrnl
            .symbol("PsLoadedModuleList")
            .and_then(|s| s.read())
        {
            Ok(v) => v,
            Err(_) if degraded => VirtAddr(0),
            Err(e) => return Err(e),
        };

        Ok(StartupMessage {
            build_number,
            base_address,
            loaded_module_list,
        })
    }
}
