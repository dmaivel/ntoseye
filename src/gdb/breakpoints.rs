use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use pelite::pe64::{Pe, PeView, image::IMAGE_SCN_MEM_EXECUTE};

use crate::backend::MemoryOps;
use crate::dbg_backend::{
    DebugBackend, DebugCapability, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, WatchpointAccess,
    validate_hw_breakpoint,
};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, ProcessInfo, read_pe_image};
use crate::target::Target;
use crate::types::{Arch, Dtb, VirtAddr};

/// A hardware (debug-register) breakpoint's parameters: the access it traps on,
/// the watch width in bytes, and which DR slot (0-3) it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareBreakpoint {
    pub access: HwBreakpointAccess,
    pub len: u8,
    pub slot: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointSpec {
    Symbol(String),
    Source {
        raw: String,
        file: String,
        line: u32,
        address_index: usize,
    },
}

impl BreakpointSpec {
    pub fn source(raw: &str, address_index: usize) -> Option<Self> {
        let (file, line) = raw.rsplit_once(':')?;
        let line = line.parse().ok()?;
        (!file.is_empty()).then(|| Self::Source {
            raw: raw.to_string(),
            file: file.to_string(),
            line,
            address_index,
        })
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Symbol(symbol) => symbol,
            Self::Source { raw, .. } => raw,
        }
    }

    fn resolve(&self, debugger: &Target, dtb: Dtb) -> Result<Option<VirtAddr>> {
        match self {
            Self::Symbol(symbol) => debugger.symbols.find_symbol_across_modules(dtb, symbol),
            Self::Source {
                file,
                line,
                address_index,
                ..
            } => Ok(debugger
                .symbols
                .source_addresses(dtb, file, *line)
                .get(*address_index)
                .copied()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    /// Last resolved address. Use [`Self::resolved_address`] when deciding
    /// whether a backend breakpoint is currently installed.
    pub address: VirtAddr,
    pub enabled: bool,
    /// Display name for the current resolution.
    pub symbol: Option<String>,
    /// Original deferred specification (`bu`/`bm`), kept across re-resolution.
    pub spec: Option<BreakpointSpec>,
    pub resolved: bool,
    pub scope: BreakpointScope,
    /// Whether `scope` was inferred from the resolved address and the process
    /// selected when this breakpoint was created. Explicit `/p` scopes remain
    /// fixed across symbol re-resolution.
    automatic_scope: bool,
    pub condition: Option<String>,
    pub condition_expr: Option<Arc<Expr>>,
    /// Requested hit number. Zero and one both mean "break on the first hit".
    pub pass_count: u64,
    pub hit_count: u64,
    pub remaining_pass_count: u64,
    pub one_shot: bool,
    pub action: Option<String>,
    pub temporary: bool,
    /// Transport-specific breakpoint state; hosts use [`Self::watchpoint`] for
    /// the semantic data-watch metadata.
    pub hardware: Option<HardwareBreakpoint>,
    backend: BreakpointBackend,
}

impl Breakpoint {
    pub fn resolved_address(&self) -> Option<VirtAddr> {
        self.resolved.then_some(self.address)
    }

    pub fn deferred(&self) -> bool {
        self.spec.is_some() && !self.resolved
    }

    pub fn specification(&self) -> Option<&str> {
        self.spec.as_ref().map(BreakpointSpec::label)
    }

    fn should_evaluate_after_hit(&self) -> bool {
        self.remaining_pass_count == 0
    }

    /// Data-watch semantics for this stop point. Execute-only debug-register
    /// breakpoints remain code breakpoints and deliberately return `None`.
    pub fn watchpoint(&self) -> Option<(WatchpointAccess, u8)> {
        let hardware = self.hardware?;
        let access = match hardware.access {
            HwBreakpointAccess::Write => WatchpointAccess::Write,
            HwBreakpointAccess::ReadWrite => WatchpointAccess::ReadWrite,
            HwBreakpointAccess::Execute => return None,
        };
        Some((access, hardware.len))
    }

    /// The watched access name (`"write"`/`"read_write"`), or `None` for a
    /// code breakpoint. Presentation surfaces share this instead of
    /// destructuring [`Self::watchpoint`] themselves.
    pub fn watch_access_name(&self) -> Option<&'static str> {
        self.watchpoint().map(|(access, _)| access.name())
    }

    /// The watched byte width, or `None` for a code breakpoint.
    pub fn watch_length(&self) -> Option<u8> {
        self.watchpoint().map(|(_, length)| length)
    }

    /// Evaluate the condition compiled when this breakpoint was installed.
    /// Unconditional breakpoints always hold.
    pub fn evaluate_condition(&self, target: &Target) -> Result<bool> {
        match &self.condition_expr {
            Some(expr) => Ok(expr.resolve(target)?.0 != 0),
            None => Ok(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointScope {
    Kernel,
    Process { pid: u64, dtb: Dtb, name: String },
}

impl BreakpointScope {
    pub fn process(process: &ProcessInfo) -> Self {
        Self::Process {
            pid: process.pid,
            dtb: process.dtb,
            name: process.name.clone(),
        }
    }

    pub fn matches_cr3(&self, cr3: u64) -> bool {
        // Mask out the PCID (bits 0..11) and reserved/canonical bits
        // (52..63), leaving only the page-directory base physical frame.
        const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        match self {
            Self::Kernel => true,
            Self::Process { dtb, .. } => (cr3 & CR3_PAGE_MASK) == (*dtb & CR3_PAGE_MASK),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kernel => "global".to_string(),
            Self::Process { pid, name, .. } => format!("{name} ({pid})"),
        }
    }
}

/// Who owns the patched instruction for a breakpoint.
///
/// * `Kernel`: written through the target's debugger API
///   (`DbgKdWriteBreakPointApi` / gdb `Z0`). The target tracks the original
///   instruction and handles step-over.
/// * `GuestMemoryPatch`: the AMD64 user-process path writes `0xCC` through the
///   live VM memory handle against a specific process page table. KD has no
///   per-process breakpoint primitive: its API uses the current CR3. Writing
///   the physical frame bypasses copy-on-write, so every process mapping that
///   frame sees the trap; the CR3 filter discards wrong-process hits, though
///   those processes still pay for the exception.
/// * `Hardware`: an x86 debug-register watch (`ba`). No memory is modified —
///   the CPU traps on the linear address — so there is no displaced byte and no
///   step-over dance. The DR slot and watch parameters live on
///   [`Breakpoint::hardware`]; hits are identified by DR6, not by RIP, so
///   hardware breakpoints stay out of the int3-hit predicates.
#[derive(Debug, Clone, Copy)]
struct BreakpointPatch {
    bytes: [u8; 4],
    len: u8,
}

impl BreakpointPatch {
    fn new(len: usize) -> Self {
        debug_assert!((1..=4).contains(&len));
        Self {
            bytes: [0; 4],
            len: len as u8,
        }
    }

    #[cfg(test)]
    fn single(byte: u8) -> Self {
        let mut patch = Self::new(1);
        patch.bytes[0] = byte;
        patch
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len as usize;
        &mut self.bytes[..len]
    }
}

#[derive(Debug, Clone)]
enum BreakpointBackend {
    Kernel { original: BreakpointPatch },
    GuestMemoryPatch { original: BreakpointPatch },
    Hardware,
    Deferred,
}

impl BreakpointBackend {
    /// The instruction bytes we displaced with the breakpoint, so display
    /// paths can overlay them and never show our own patch (1 byte for an
    /// x86 `int3`, 4 for an AArch64 `brk #0xF000`). Hardware breakpoints
    /// displace nothing (they never reach the masking path).
    fn original_bytes(&self) -> &[u8] {
        match self {
            Self::Kernel { original } | Self::GuestMemoryPatch { original } => original.as_slice(),
            Self::Hardware | Self::Deferred => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointHitDisposition {
    SkipPass,
    Evaluate,
}
#[derive(Debug, Clone, Default)]
pub struct BreakpointConfig {
    pub condition: Option<String>,
    pub condition_expr: Option<Arc<Expr>>,
    pub pass_count: u64,
    pub one_shot: bool,
    pub action: Option<String>,
    pub scope: Option<BreakpointScope>,
}

#[derive(Default)]
pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    one_shot_hits: HashSet<u32>,
    next_id: u32,
}

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
    /// kernel int3 with a dummy displaced byte. Lets tests outside this
    /// module (session run-control) stage manager state without a live
    /// target.
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
                original: BreakpointPatch::single(0x90),
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
        let condition_expr = Self::compile_condition(condition.as_deref())?;
        self.add_code_configured(
            client,
            debugger,
            Some(address),
            symbol,
            None,
            false,
            BreakpointConfig {
                condition,
                condition_expr,
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
        self.add_code_configured(client, debugger, Some(address), symbol, None, false, config)
    }

    pub fn add_symbolic(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        symbol: String,
        config: BreakpointConfig,
    ) -> Result<u32> {
        let spec = BreakpointSpec::Symbol(symbol.clone());
        let dtb = Self::resolution_dtb(debugger, config.scope.as_ref());
        let address = spec.resolve(debugger, dtb)?;
        self.add_code_configured(
            client,
            debugger,
            address,
            Some(symbol),
            Some(spec),
            false,
            config,
        )
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
            return Err(Error::Rsp(format!("invalid source breakpoint: {source}")));
        };
        let dtb = Self::resolution_dtb(debugger, config.scope.as_ref());
        let address_count = match &first_spec {
            BreakpointSpec::Source { file, line, .. } => {
                debugger.symbols.source_addresses(dtb, file, *line).len()
            }
            BreakpointSpec::Symbol(_) => unreachable!(),
        };
        let count = address_count.max(1);
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let result = (|| {
                let spec = BreakpointSpec::source(&source, index)
                    .ok_or_else(|| Error::Rsp(format!("invalid source breakpoint: {source}")))?;
                let address = spec.resolve(debugger, dtb)?;
                self.add_code_configured(
                    client,
                    debugger,
                    address,
                    Some(source.clone()),
                    Some(spec),
                    false,
                    config.clone(),
                )
            })();

            match result {
                Ok(id) => ids.push(id),
                Err(error) => {
                    if let Err(rollback_error) =
                        self.remove_ids(client, debugger, ids.iter().rev().copied())
                    {
                        return Err(Error::Rsp(format!(
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

    pub fn add_temporary_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
    ) -> Result<u32> {
        self.add_code_configured(
            client,
            debugger,
            Some(address),
            None,
            None,
            true,
            BreakpointConfig::default(),
        )
    }

    fn add_code_configured(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: Option<VirtAddr>,
        symbol: Option<String>,
        spec: Option<BreakpointSpec>,
        temporary: bool,
        config: BreakpointConfig,
    ) -> Result<u32> {
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
        Self::validate_scope_capability(client, &scope)?;

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
                condition_expr: config.condition_expr,
                pass_count,
                hit_count: 0,
                remaining_pass_count: pass_count.saturating_sub(1),
                one_shot: config.one_shot,
                action: config.action,
                temporary,
                hardware: None,
                backend,
            },
        );
        Ok(id)
    }

    fn validate_scope_capability(client: &dyn DebugBackend, scope: &BreakpointScope) -> Result<()> {
        let capability = match scope {
            BreakpointScope::Kernel => DebugCapability::KernelBreakpoints,
            BreakpointScope::Process { .. } => DebugCapability::UserModeBreakpoints,
        };
        if client
            .capabilities()
            .iter()
            .any(|c| c.capability == capability && c.supported)
        {
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }

    /// Set a hardware (debug-register) breakpoint. String conditions use the
    /// core decimal expression contract.
    pub fn add_hardware(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        let condition_expr = Self::compile_condition(condition.as_deref())?;
        self.add_hardware_configured(
            client,
            debugger,
            address,
            access,
            len,
            symbol,
            BreakpointConfig {
                condition,
                condition_expr,
                ..BreakpointConfig::default()
            },
        )
    }

    pub fn add_hardware_configured(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        if !client.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        validate_hw_breakpoint(access, len, address.0)?;
        self.ensure_site_available(address, true, None)?;
        let slot = self.free_hardware_slot()?;
        let automatic_scope = config.scope.is_none();
        let fallback_scope = config
            .scope
            .unwrap_or_else(|| Self::scope_for_current_context(debugger));
        let scope = if automatic_scope {
            Self::scope_for_address(debugger, address, &fallback_scope)
        } else {
            fallback_scope
        };
        client.set_hardware_breakpoint(slot, address.0, access, len)?;

        let id = self.next_id;
        self.next_id += 1;
        let pass_count = config.pass_count;
        self.breakpoints.insert(
            id,
            Breakpoint {
                id,
                address,
                enabled: true,
                symbol,
                spec: None,
                resolved: true,
                scope,
                automatic_scope,
                condition: config.condition,
                condition_expr: config.condition_expr,
                pass_count,
                hit_count: 0,
                remaining_pass_count: pass_count.saturating_sub(1),
                one_shot: config.one_shot,
                action: config.action,
                temporary: false,
                hardware: Some(HardwareBreakpoint { access, len, slot }),
                backend: BreakpointBackend::Hardware,
            },
        );
        Ok(id)
    }

    fn compile_condition(condition: Option<&str>) -> Result<Option<Arc<Expr>>> {
        condition
            .map(Expr::parse)
            .transpose()
            .map(|expr| expr.map(Arc::new))
    }

    /// The lowest DR slot (0-3) not already claimed by a hardware breakpoint,
    /// or an error when all four are in use. Disabled hardware breakpoints keep
    /// their slot reserved (matching WinDbg's fixed four).
    fn free_hardware_slot(&self) -> Result<u8> {
        (0..HW_BREAKPOINT_SLOTS)
            .find(|slot| {
                !self
                    .breakpoints
                    .values()
                    .any(|bp| bp.hardware.is_some_and(|hw| hw.slot == *slot))
            })
            .ok_or_else(|| {
                Error::Rsp(format!(
                    "all {HW_BREAKPOINT_SLOTS} hardware breakpoint slots are in use"
                ))
            })
    }

    pub fn remove(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        self.remove_if_uninstalled(id, |bp| Self::uninstall_breakpoint(client, debugger, bp))
    }

    fn remove_ids(
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
            Err(Error::Rsp(format!(
                "failed to uninstall breakpoints: {}",
                failures.join("; ")
            )))
        }
    }

    pub fn discard(&mut self, id: u32) -> Result<Breakpoint> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        self.one_shot_hits.remove(&id);
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        Ok(bp)
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
            let backend = if matches!(snapshot.backend, BreakpointBackend::Deferred) {
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
                client.note_breakpoint_uninstalled(bp.address.0);
                bp.enabled = false;
                Ok(())
            }
            BreakpointBackend::Kernel { .. } => Err(Error::Rsp(
                "cannot address-space-disable a kernel breakpoint".into(),
            )),
            BreakpointBackend::Hardware => Err(Error::Rsp(
                "cannot address-space-disable a hardware breakpoint".into(),
            )),
            BreakpointBackend::Deferred => {
                bp.enabled = false;
                Ok(())
            }
        }
    }
    pub fn managed_ids(&self) -> Vec<u32> {
        self.breakpoints.keys().copied().collect()
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

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints
            .values()
            .any(|bp| bp.enabled && bp.resolved)
    }

    /// Whether any enabled hardware (DR) breakpoint exists — the cheap gate the
    /// stop path checks before reading DR6 on a single-step.
    pub fn has_enabled_hardware_breakpoints(&self) -> bool {
        self.breakpoints
            .values()
            .any(|bp| bp.enabled && bp.hardware.is_some())
    }

    /// The enabled hardware breakpoint occupying DR slot `slot`, if any — used
    /// to map a DR6 status bit back to the breakpoint that fired.
    pub fn hardware_breakpoint_for_slot(&self, slot: u8) -> Option<Breakpoint> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.hardware.is_some_and(|hw| hw.slot == slot))
            .cloned()
    }

    /// Best-effort release of every DR slot held by a hardware breakpoint
    /// (enabled or not — disabled ones still reserve their slot). Used by the
    /// target-reload path before it drops the manager: after a real reboot the
    /// debug registers are reset anyway, but a reload without a machine reset
    /// (kernel rediscovery) would otherwise leave orphaned watches raising
    /// `#DB`s no manager entry can claim.
    pub fn clear_hardware_slots(&self, client: &mut dyn DebugBackend) {
        for bp in self.breakpoints.values() {
            if let Some(hw) = bp.hardware {
                let _ = client.clear_hardware_breakpoint(hw.slot);
            }
        }
    }

    // NOTE refreshing ensures local breakpoint state matches target state in case they were cleared,
    // this should fix single stepping breaking every breakpoint proceeding the step..
    pub fn refresh_enabled(&self, client: &mut dyn DebugBackend, debugger: &Target) -> Result<()> {
        let mut enabled: Vec<_> = self
            .breakpoints
            .values()
            .filter(|bp| bp.enabled && bp.resolved && bp.hardware.is_none())
            .collect();
        enabled.sort_by_key(|bp| bp.id);

        for bp in enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, bp);
            Self::install_existing_breakpoint(client, debugger, bp)?;
        }

        Ok(())
    }

    /// Record a physical hit before pass-count and condition handling.
    pub fn record_hit(&mut self, id: u32) -> Result<BreakpointHitDisposition> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.hit_count = bp.hit_count.saturating_add(1);
        if bp.remaining_pass_count > 0 {
            bp.remaining_pass_count -= 1;
            Ok(BreakpointHitDisposition::SkipPass)
        } else {
            debug_assert!(bp.should_evaluate_after_hit());
            Ok(BreakpointHitDisposition::Evaluate)
        }
    }

    pub fn set_pass_count(&mut self, id: u32, pass_count: u64) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.pass_count = pass_count;
        bp.remaining_pass_count = pass_count.saturating_sub(1);
        Ok(())
    }

    pub fn set_one_shot(&mut self, id: u32, one_shot: bool) -> Result<()> {
        self.breakpoints
            .get_mut(&id)
            .ok_or(Error::BPNotFound(id))?
            .one_shot = one_shot;
        Ok(())
    }

    pub fn set_action(&mut self, id: u32, action: Option<String>) -> Result<()> {
        self.breakpoints
            .get_mut(&id)
            .ok_or(Error::BPNotFound(id))?
            .action = action;
        Ok(())
    }
    pub fn mark_one_shot_hit(&mut self, id: u32) -> Result<()> {
        let bp = self.breakpoints.get(&id).ok_or(Error::BPNotFound(id))?;
        if bp.one_shot {
            self.one_shot_hits.insert(id);
        }
        Ok(())
    }

    pub fn one_shot_hit_ids(&self) -> Vec<u32> {
        self.one_shot_hits.iter().copied().collect()
    }

    pub fn set_condition(
        &mut self,
        id: u32,
        condition: Option<String>,
        condition_expr: Option<Arc<Expr>>,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.condition = condition;
        bp.condition_expr = condition_expr;
        Ok(())
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
        let kernel_dtb = debugger.kernel_dtb();
        self.defer_symbolic_sites_if(|bp| {
            let primary_dtb = Self::resolution_dtb(debugger, Some(&bp.scope));
            debugger
                .symbols
                .find_module_for_address_in_context(primary_dtb, kernel_dtb, bp.address)
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
        for id in ids {
            let snapshot = self
                .breakpoints
                .get(&id)
                .cloned()
                .ok_or(Error::BPNotFound(id))?;
            let spec = snapshot
                .spec
                .as_ref()
                .ok_or_else(|| Error::Rsp(format!("breakpoint {id} lost its specification")))?;
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

            if let Some(address) = resolved {
                Self::validate_scope_capability(client, &scope)?;
                Self::validate_breakpoint_target(debugger, address, &scope)?;
                self.ensure_site_available(address, false, Some(id))?;
            }

            if snapshot.resolved && snapshot.enabled {
                Self::uninstall_breakpoint(client, debugger, &snapshot)?;
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
                                return Err(Error::Rsp(format!(
                                    "failed to move breakpoint {id}: {install_error}; restoring its previous installation also failed: {rollback_error}"
                                )));
                            }
                            return Err(install_error);
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
        Ok(resolved_count)
    }

    pub fn check_breakpoint_hit(&self, rip: u64, cr3: u64) -> BreakpointHitResult {
        for bp in self.breakpoints.values() {
            if !self.one_shot_hits.contains(&bp.id)
                && bp.resolved
                && bp.hardware.is_none()
                && bp.address.0 == rip
                && bp.enabled
                && bp.scope.matches_cr3(cr3)
            {
                return BreakpointHitResult::Hit(bp.clone());
            }
        }

        BreakpointHitResult::NotBreakpoint
    }

    pub fn enabled_breakpoint_id_for_current_context(
        &self,
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<u32> {
        let cr3 = debugger.current_dtb();
        self.breakpoints
            .values()
            .filter(|bp| {
                bp.resolved
                    && bp.enabled
                    && bp.hardware.is_none()
                    && bp.address == address
                    && bp.scope.matches_cr3(cr3)
            })
            .map(|bp| bp.id)
            .min()
    }

    #[cfg(test)]
    fn enabled_software_breakpoint_id(
        &self,
        scope: &BreakpointScope,
        address: VirtAddr,
    ) -> Option<u32> {
        self.breakpoints
            .values()
            .filter(|bp| {
                bp.resolved
                    && bp.enabled
                    && bp.hardware.is_none()
                    && bp.address == address
                    && &bp.scope == scope
            })
            .map(|bp| bp.id)
            .min()
    }

    /// Overlay our breakpoints' original bytes onto a buffer read for display,
    /// so no view ever shows the int3 we injected. `start` is the buffer's
    /// guest VA; `cr3` scopes process breakpoints to the address space the
    /// bytes were read from (kernel breakpoints are global).
    pub fn mask_breakpoint_bytes(&self, start: VirtAddr, buf: &mut [u8], cr3: u64) {
        let end = start.0.wrapping_add(buf.len() as u64);
        for bp in self.breakpoints.values() {
            if !bp.resolved || !bp.enabled || bp.hardware.is_some() || !bp.scope.matches_cr3(cr3) {
                continue;
            }
            if bp.address.0 < start.0 || bp.address.0 >= end {
                continue;
            }
            let offset = (bp.address.0 - start.0) as usize;
            let bytes = bp.backend.original_bytes();
            if offset + bytes.len() <= buf.len() {
                buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            }
        }
    }

    /// Find a BP at `rip` regardless of its scope; "is this int3 owned by us?"
    pub fn breakpoint_id_at_address(&self, rip: u64) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| bp.resolved && bp.enabled && bp.hardware.is_none() && bp.address.0 == rip)
            .map(|bp| bp.id)
    }

    fn ensure_site_available(
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
            return Err(Error::Rsp(format!(
                "{kind} breakpoint {} already owns address {:#x}",
                existing.id, address.0
            )));
        }
        Ok(())
    }

    fn scope_for_current_context(debugger: &Target) -> BreakpointScope {
        match &debugger.current_process_info {
            Some(ProcessInfo { pid, name, dtb, .. }) => BreakpointScope::Process {
                pid: *pid,
                dtb: *dtb,
                name: name.clone(),
            },
            None => BreakpointScope::Kernel,
        }
    }

    fn scope_for_address(
        debugger: &Target,
        address: VirtAddr,
        fallback: &BreakpointScope,
    ) -> BreakpointScope {
        const WINDOWS_X64_KERNEL_START: u64 = 0xffff_8000_0000_0000;
        if address.0 >= WINDOWS_X64_KERNEL_START
            || Self::find_kernel_module_containing_address(debugger, address).is_some()
        {
            BreakpointScope::Kernel
        } else {
            fallback.clone()
        }
    }

    fn install_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<BreakpointBackend> {
        match scope {
            BreakpointScope::Kernel => {
                // Capture the displaced instruction before the kernel writes
                // the breakpoint, so display paths can mask it back out. x86
                // `int3` displaces one byte; AArch64 `brk #0xF000` displaces
                // four.
                let memory = debugger.address_space(debugger.current_dtb());
                let width = match debugger.arch() {
                    Arch::Amd64 => 1,
                    Arch::Arm64 => 4,
                };
                let mut original = BreakpointPatch::new(width);
                memory.read_bytes(address, original.as_mut_slice())?;
                client.set_breakpoint(address.0)?;
                Ok(BreakpointBackend::Kernel { original })
            }
            BreakpointScope::Process { dtb, .. } => {
                let memory = debugger.address_space(*dtb);
                let mut original = BreakpointPatch::new(1);
                memory.read_bytes(address, original.as_mut_slice())?;
                memory.write_bytes(address, &[0xcc])?;
                // The kernel does not know about a breakpoint patched through
                // host memory, so update the backend's stop bookkeeping.
                client.note_breakpoint_installed(address.0);
                Ok(BreakpointBackend::GuestMemoryPatch { original })
            }
        }
    }

    fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.set_breakpoint(bp.address.0)
            }
            (BreakpointScope::Process { dtb, .. }, BreakpointBackend::GuestMemoryPatch { .. }) => {
                let memory = debugger.address_space(*dtb);
                memory.write_bytes(bp.address, &[0xcc])?;
                client.note_breakpoint_installed(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => {
                    client.set_hardware_breakpoint(hw.slot, bp.address.0, hw.access, hw.len)
                }
                None => Err(Error::Rsp("hardware breakpoint missing parameters".into())),
            },
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn uninstall_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.remove_breakpoint(bp.address.0)
            }
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original },
            ) => {
                let memory = debugger.address_space(*dtb);
                memory.write_bytes(bp.address, original.as_slice())?;
                client.note_breakpoint_uninstalled(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => client.clear_hardware_breakpoint(hw.slot),
                None => Err(Error::Rsp("hardware breakpoint missing parameters".into())),
            },
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn validate_breakpoint_target(
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<()> {
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let dtb = match scope {
            BreakpointScope::Kernel => debugger.kernel_dtb(),
            BreakpointScope::Process { dtb, .. } => *dtb,
        };
        let memory = debugger.address_space(dtb);
        let translation = memory
            .virt_to_phys(address)?
            .ok_or(Error::BadVirtualAddress(address))?;

        // AArch64 table-level execute restrictions depend on TCR_EL1
        // hierarchical-permission controls, which passive memory inspection
        // does not capture. Do not reject a TTBR1 address solely from descriptor
        // bits; known kernel modules are still checked against PE executable
        // sections below. TTBR0 user pages can be classified by effective UXN.
        let nx = match (debugger.arch(), address.0 & (1 << 55) != 0) {
            (Arch::Arm64, true) => false,
            (Arch::Arm64, false) => translation.uxn,
            _ => translation.nx,
        };

        if nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::Breakpoint(format!(
                "refusing breakpoint at {:#x}: target page is non-executable ({})",
                address.0, context
            )));
        }

        if let Some(module) = module {
            let image = read_pe_image(module.base_address, &memory)?;
            let view = PeView::from_bytes(image.as_slice())?;
            let rva = address.0.saturating_sub(module.base_address.0) as u32;
            let in_executable_section = view.section_headers().iter().any(|section| {
                let size = section.VirtualSize.max(section.SizeOfRawData);
                size != 0
                    && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && rva >= section.VirtualAddress
                    && rva < section.VirtualAddress.saturating_add(size)
            });

            if !in_executable_section {
                return Err(Error::Breakpoint(format!(
                    "refusing breakpoint at {:#x}: address falls in non-executable section of {}",
                    address.0, module.short_name
                )));
            }
        }

        Ok(())
    }

    fn find_kernel_module_containing_address(
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<ModuleInfo> {
        debugger
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.contains_address(address))
    }
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(Breakpoint),
    /// Program counter does not match any breakpoint.
    NotBreakpoint,
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{
        Breakpoint, BreakpointBackend, BreakpointHitDisposition, BreakpointHitResult,
        BreakpointManager, BreakpointPatch, BreakpointScope, BreakpointSpec, HardwareBreakpoint,
    };
    use crate::dbg_backend::{DebugBackend, HwBreakpointAccess, StopEvent, WatchpointAccess};
    use crate::error::{Error, Result};
    use crate::expr::{Expr, ExprBinaryOp, NumberRadix};
    use crate::gdb::RegisterMap;
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
    fn exposes_data_watches_without_transport_metadata() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::ReadWrite,
                len: 8,
                slot: 2,
            }),
        );

        let breakpoint = manager.list().into_iter().find(|bp| bp.id == 7).unwrap();
        assert_eq!(
            breakpoint.watchpoint(),
            Some((WatchpointAccess::ReadWrite, 8))
        );
    }

    #[test]
    fn detects_breakpoint_hit_at_exact_rip() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x1000),
                enabled: true,
                symbol: None,
                spec: None,
                resolved: true,
                scope: BreakpointScope::Kernel,
                automatic_scope: false,
                condition: None,
                condition_expr: None,
                pass_count: 0,
                hit_count: 0,
                remaining_pass_count: 0,
                one_shot: false,
                action: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::Kernel {
                    original: BreakpointPatch::single(0x90),
                },
            },
        );

        match manager.check_breakpoint_hit(0x1000, 0) {
            BreakpointHitResult::Hit(bp) => assert_eq!(bp.id, 0),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn process_breakpoint_hit_requires_matching_cr3() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x7ff7_1234_1000),
                enabled: true,
                symbol: None,
                spec: None,
                resolved: true,
                scope: BreakpointScope::Process {
                    pid: 42,
                    dtb: 0x1234_5000,
                    name: "user.exe".to_string(),
                },
                automatic_scope: false,
                condition: None,
                condition_expr: None,
                pass_count: 0,
                hit_count: 0,
                remaining_pass_count: 0,
                one_shot: false,
                action: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::GuestMemoryPatch {
                    original: BreakpointPatch::single(0x90),
                },
            },
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5000),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5fff),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x9999_9000),
            BreakpointHitResult::NotBreakpoint
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_4000),
            BreakpointHitResult::NotBreakpoint
        ));
    }

    #[test]
    fn hardware_breakpoint_is_ignored_by_int3_hit_predicates() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            0,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        // A DR watch traps via DR6, not RIP, so it must never register as an
        // int3 hit even when the faulting RIP equals its address.
        assert!(matches!(
            manager.check_breakpoint_hit(0x2000, 0),
            BreakpointHitResult::NotBreakpoint
        ));
        assert_eq!(manager.breakpoint_id_at_address(0x2000), None);
    }

    #[test]
    fn has_enabled_hardware_breakpoints_tracks_enabled_hw_bps() {
        let mut manager = BreakpointManager::new();

        // Software breakpoints do not count toward the DR6 gate.
        manager.insert_for_test(0, VirtAddr(0x1000), true, None);
        assert!(!manager.has_enabled_hardware_breakpoints());

        // An enabled hardware breakpoint opens the gate.
        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );
        assert!(manager.has_enabled_hardware_breakpoints());

        // Disabling that same hardware breakpoint closes it again.
        manager.breakpoints.get_mut(&1).unwrap().enabled = false;
        assert!(!manager.has_enabled_hardware_breakpoints());
    }

    #[test]
    fn hardware_breakpoint_for_slot_resolves_enabled_slot_only() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x3000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::ReadWrite,
                len: 8,
                slot: 1,
            }),
        );

        let found = manager
            .hardware_breakpoint_for_slot(1)
            .expect("slot 1 hw bp");
        assert_eq!(found.id, 7);
        assert_eq!(found.hardware.expect("hw params").slot, 1);

        // Nothing occupies slot 0.
        assert!(manager.hardware_breakpoint_for_slot(0).is_none());

        // A disabled hw bp in slot 0 must not be resolved either.
        manager.insert_for_test(
            8,
            VirtAddr(0x4000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 2,
                slot: 0,
            }),
        );
        assert!(manager.hardware_breakpoint_for_slot(0).is_none());
    }

    #[test]
    fn software_and_hardware_breakpoint_coexist_at_same_address() {
        let mut manager = BreakpointManager::new();
        let addr = 0x5000;

        // Software int3 and a DR watch pinned to the same linear address.
        manager.insert_for_test(0, VirtAddr(addr), true, None);
        manager.insert_for_test(
            1,
            VirtAddr(addr),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        // The int3 predicate resolves the software bp; the DR watch is skipped
        // regardless of HashMap iteration order.
        match manager.check_breakpoint_hit(addr, 0) {
            BreakpointHitResult::Hit(bp) => {
                assert_eq!(bp.id, 0);
                assert!(bp.hardware.is_none());
            }
            other => panic!("expected software hit, got {:?}", other),
        }
        assert_eq!(manager.breakpoint_id_at_address(addr), Some(0));
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            Some(0)
        );

        // A data watch alone cannot satisfy run-to-address: it fires on a data
        // access, not when execution reaches the watched linear address.
        manager.breakpoints.remove(&0);
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            None
        );
    }

    #[test]
    fn condition_compiler_accepts_the_full_expression_grammar() {
        let source = "$rax == 1 && ($rcx & 0xff) != 0";
        let compiled = BreakpointManager::compile_condition(Some(source))
            .unwrap()
            .expect("compiled condition");
        assert!(matches!(
            compiled.as_ref(),
            Expr::Binary(_, ExprBinaryOp::LogicalAnd, _)
        ));

        assert!(
            BreakpointManager::compile_condition(None)
                .unwrap()
                .is_none()
        );
        assert!(BreakpointManager::compile_condition(Some("$rax == ")).is_err());
    }

    #[test]
    fn pass_count_records_every_hit_and_surfaces_requested_hit() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(3, VirtAddr(0x1000), true, None);
        manager.set_pass_count(3, 3).unwrap();

        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::SkipPass
        );
        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::SkipPass
        );
        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::Evaluate
        );
        let bp = manager.list()[0];
        assert_eq!(bp.hit_count, 3);
        assert_eq!(bp.remaining_pass_count, 0);
    }

    #[test]
    fn one_shot_is_hidden_after_surface_but_remains_available_for_safe_step_over() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(4, VirtAddr(0x2000), true, None);
        manager.set_one_shot(4, true).unwrap();
        manager.mark_one_shot_hit(4).unwrap();

        assert!(manager.list().is_empty());
        assert_eq!(manager.breakpoint_id_at_address(0x2000), Some(4));
        assert_eq!(manager.one_shot_hit_ids(), vec![4]);
        manager.discard(4).unwrap();
        assert!(manager.one_shot_hit_ids().is_empty());
    }

    #[test]
    fn target_reload_keeps_symbolic_identity_deferred_and_drops_numeric_points() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(1, VirtAddr(0x1000), true, None);
        manager.insert_for_test(7, VirtAddr(0x2000), true, None);
        {
            let symbolic = manager.breakpoints.get_mut(&7).unwrap();
            symbolic.symbol = Some("driver!Entry".into());
            symbolic.spec = Some(BreakpointSpec::Symbol("driver!Entry".into()));
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

        assert_eq!(manager.defer_symbolic_sites_if(|bp| bp.id == 3), 1);

        let deferred = manager.breakpoints.get(&3).unwrap();
        assert!(deferred.enabled);
        assert!(deferred.deferred());
        assert_eq!(deferred.address, VirtAddr(0x3000));
        assert!(matches!(deferred.backend, BreakpointBackend::Deferred));
        assert!(manager.breakpoints.get(&4).unwrap().resolved);
        assert!(matches!(
            manager.check_breakpoint_hit(0x3000, 0),
            BreakpointHitResult::NotBreakpoint
        ));
    }

    #[test]
    fn parsed_condition_keeps_creation_radix_and_action_classification() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(9, VirtAddr(0x3000), true, None);
        let expr = Expr::parse_with_radix("10 == 0x10", NumberRadix::Hexadecimal).unwrap();
        manager
            .set_condition(9, Some("10 == 0x10".into()), Some(Arc::new(expr)))
            .unwrap();
        manager.set_action(9, Some("r; gc".to_string())).unwrap();

        let bp = match manager.check_breakpoint_hit(0x3000, 0) {
            BreakpointHitResult::Hit(bp) => bp,
            other => panic!("unexpected result: {other:?}"),
        };
        assert!(matches!(
            bp.condition_expr.as_deref(),
            Some(Expr::Binary(
                left,
                ExprBinaryOp::Equal,
                right
            )) if matches!(left.as_ref(), Expr::Literal(VirtAddr(0x10)))
                && matches!(right.as_ref(), Expr::Literal(VirtAddr(0x10)))
        ));
        assert_eq!(bp.action.as_deref(), Some("r; gc"));
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

    /// Backend stub that records which DR slots `clear_hardware_breakpoint`
    /// releases; every other operation is out of scope for these tests.
    struct SlotRecorder {
        register_map: RegisterMap,
        cleared: Vec<u8>,
    }

    impl SlotRecorder {
        fn new() -> Self {
            Self {
                register_map: RegisterMap::default(),
                cleared: Vec::new(),
            }
        }
    }

    impl DebugBackend for SlotRecorder {
        fn register_map(&self) -> &RegisterMap {
            &self.register_map
        }
        fn read_registers(&mut self) -> Result<Vec<u8>> {
            Err(Error::NotSupported)
        }
        fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
            self.cleared.push(slot);
            Ok(())
        }
        fn continue_execution(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn step(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn interrupt(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn wait_for_stop(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
            Ok(None)
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
            false
        }
    }

    #[test]
    fn clear_hardware_slots_releases_every_hw_slot_and_skips_software() {
        let mut manager = BreakpointManager::new();
        // Enabled DR watch occupying slot 2.
        manager.insert_for_test(
            0,
            VirtAddr(0x1000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 2,
            }),
        );
        // A disabled DR watch still reserves slot 0 and must be released too.
        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot: 0,
            }),
        );
        // Software int3: no DR slot, must never reach the backend.
        manager.insert_for_test(2, VirtAddr(0x3000), true, None);

        let mut backend = SlotRecorder::new();
        manager.clear_hardware_slots(&mut backend);

        // Exactly the two hardware slots, nothing for the software bp.
        let mut cleared = backend.cleared.clone();
        cleared.sort_unstable();
        assert_eq!(cleared, vec![0, 2]);
    }
}
