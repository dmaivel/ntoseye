use std::collections::BTreeMap;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::backend::dbg_backend::DebugBackend;
use crate::base::types::{Dtb, VirtAddr};
use crate::nt::breakpoints::BreakpointManager;
use crate::nt::guest::ProcessInfo;
use crate::nt::symbols::{SymbolIndex, SymbolStore};
use crate::nt::target::object::DriverObjectInfo;
use crate::nt::target::{Target, ThreadInfo};

const PROCESS_COMPLETION_LIMIT: usize = 4096;

/// [`ReplCaches::indexed_at`] of symbol and type indexes not built yet. The
/// store's load generation counts up from zero and never reaches it.
pub const NOT_INDEXED: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionStrategy {
    None,
    Symbol,
    Expression,
    Type,
    Process,
    Thread,
    Vcpu,
    Breakpoint,
    Driver,
    Alias,
    /// A full registry key path, completed one key at a time.
    RegistryKey,
}

impl CompletionStrategy {
    pub fn from_kebab(s: &str) -> Option<Self> {
        Some(match s {
            "none" | "" => Self::None,
            "symbol" => Self::Symbol,
            "expression" => Self::Expression,
            "type" => Self::Type,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "vcpu" => Self::Vcpu,
            "breakpoint" => Self::Breakpoint,
            "driver" => Self::Driver,
            "alias" => Self::Alias,
            "registry-key" => Self::RegistryKey,
            _ => return None,
        })
    }
}

/// Cached process info for completion (image name, PID).  The process command
/// accepts both forms, so completion deliberately keeps the image spelling
/// instead of reducing entries to numeric IDs.
pub type ProcessCache = Vec<(String, u64)>;

/// Cached execution-context IDs for completion
pub type VcpuCache = Vec<String>;

/// Cached Windows thread info for completion
pub type ThreadCache = Vec<ThreadInfo>;

/// Cached breakpoint info for completion (id, enabled, address, symbol)
pub type BreakpointCache = Vec<(u32, bool, VirtAddr, Option<String>)>;

/// Cached driver object info for completion
pub type DriverObjectCache = Vec<DriverObjectInfo>;

/// Cached expression variable name and display kind
pub type ExpressionVariableCache = Vec<(String, &'static str)>;

/// Cached (name, help, per-arg strategies) for script-registered commands
pub type UserCommandCache = Vec<(String, String, Vec<CompletionStrategy>)>;

/// Cached user alias definitions for completion
pub type AliasCache = Vec<(String, String)>;

/// Completion-facing state shared between the REPL loop (which rewrites the
/// caches as the target's state changes) and the tab completer. Every field is
/// a cheap-to-clone handle, so the loop and the completer each hold a clone.
#[derive(Clone)]
pub struct ReplCaches {
    pub symbols: Arc<RwLock<SymbolIndex>>,
    pub types: Arc<RwLock<SymbolIndex>>,
    pub symbol_store: Arc<SymbolStore>,
    pub dtb: Arc<RwLock<Dtb>>,
    pub processes: Arc<RwLock<ProcessCache>>,
    pub threads: Arc<RwLock<ThreadCache>>,
    pub vcpus: Arc<RwLock<VcpuCache>>,
    pub breakpoints: Arc<RwLock<BreakpointCache>>,
    pub drivers: Arc<RwLock<DriverObjectCache>>,
    pub registers: Arc<Vec<String>>,
    pub expression_variables: Arc<RwLock<ExpressionVariableCache>>,
    pub user_commands: Arc<RwLock<UserCommandCache>>,
    pub aliases: Arc<RwLock<AliasCache>>,
    /// The guest partition whose view the symbol and thread caches were
    /// built for, or 0 for the target's: no partition has ID 0, which the
    /// hypervisor reserves as invalid (see [`Self::refresh_partition`]).
    pub partition: Arc<AtomicU64>,
    /// The symbol store's load generation when `symbols` and `types` were
    /// built (see [`Self::refresh_loaded_symbols`]), or [`NOT_INDEXED`].
    /// Merging every module's names takes a noticeable part of a second
    /// with many PDBs loaded, so a host without a tab completer leaves them
    /// unbuilt until a search reads them.
    pub indexed_at: Arc<AtomicU64>,
}

impl ReplCaches {
    /// Processes for completion: enumerated from the target on demand (served
    /// from the halt memo after the first walk) and remembered as the fallback
    /// for when the target cannot be read, e.g. while the guest runs.
    pub fn processes_for_completion(&self, target: Option<&Target>) -> ProcessCache {
        if let Some(processes) = target.and_then(|target| target.matching_processes(None).ok()) {
            let processes: ProcessCache = processes
                .into_iter()
                .take(PROCESS_COMPLETION_LIMIT)
                .map(|p| (p.name, p.pid))
                .collect();
            *self.processes.write().unwrap() = processes.clone();
            return processes;
        }
        self.processes.read().unwrap().clone()
    }

    /// Remember `processes` for completion, as a listing just read them.
    pub fn remember_processes(&self, processes: &[ProcessInfo]) {
        *self.processes.write().unwrap() = processes
            .iter()
            .map(|process| (process.name.clone(), process.pid))
            .collect();
    }

    /// Driver objects for completion; same on-demand policy as
    /// [`Self::processes_for_completion`].
    pub fn drivers_for_completion(&self, target: Option<&Target>) -> DriverObjectCache {
        if let Some(drivers) = target.and_then(|target| target.enumerate_driver_objects().ok()) {
            *self.drivers.write().unwrap() = drivers.clone();
            return drivers;
        }
        self.drivers.read().unwrap().clone()
    }

    pub fn refresh_vcpus(&self, client: &mut dyn DebugBackend) {
        if let Ok(vcpus) = client.thread_list() {
            *self.vcpus.write().unwrap() = vcpus;
        }
    }

    /// The thread cache is only populated on demand (threads/thread commands);
    /// a full thread walk is far too expensive to run on every stop, especially
    /// over serial KD. Reloads just drop the now-stale entries.
    pub fn clear_threads(&self) {
        self.threads.write().unwrap().clear();
    }

    /// Snapshot the current breakpoint set into the completion cache
    pub fn refresh_breakpoints(&self, breakpoints: &BreakpointManager) {
        *self.breakpoints.write().unwrap() = breakpoints
            .list()
            .iter()
            .map(|bp| (bp.id, bp.enabled, bp.address, bp.symbol.clone()))
            .collect();
    }

    /// Rebuild the symbol/type/DTB completion caches after the active context
    /// changes (kernel reload, process attach/detach). Called on every stop, so
    /// the expensive rebuild is skipped when the DTB hasn't moved.
    pub fn refresh_symbol_context(&self, debugger: &Target) {
        let new_dtb = debugger.current_dtb();
        if *self.dtb.read().unwrap() == new_dtb {
            return;
        }
        self.rebuild_symbol_context(debugger);
    }

    /// Rebuild the symbol and thread caches for the partition view shown
    /// (`partition`, `None` for the target) when it is not the one they were
    /// built for: `.partition` changes it, a resume leaves a view, and a
    /// partition breakpoint's hit shows one. Its kernel is another, whose
    /// page-table root can equal the target's, so the DTB check of
    /// [`Self::refresh_symbol_context`] cannot tell them apart.
    pub fn refresh_partition(&self, partition: Option<u64>, debugger: &Target) {
        if self
            .partition
            .swap(partition.unwrap_or(0), Ordering::Relaxed)
            == partition.unwrap_or(0)
        {
            return;
        }
        self.clear_threads();
        self.rebuild_symbol_context(debugger);
    }

    /// Rebuild the symbol and type indexes when PDBs loaded since they were
    /// built, or build them if they never were: a module whose symbols load
    /// when first needed, or a download that finished, so completion offers
    /// its names. Anything that reads `symbols` or `types` calls this first.
    pub fn refresh_loaded_symbols(&self, debugger: &Target) {
        if debugger.symbols.load_generation() != self.indexed_at.load(Ordering::Acquire) {
            self.build_symbol_indexes(debugger);
        }
    }

    /// Rebuild the symbol and type indexes for the current context, if they
    /// were built: indexes nothing has read yet are left for
    /// [`Self::refresh_loaded_symbols`] to build.
    pub fn rebuild_symbol_context(&self, debugger: &Target) {
        if self.indexed_at.load(Ordering::Acquire) == NOT_INDEXED {
            *self.dtb.write().unwrap() = debugger.current_dtb();
            return;
        }
        self.build_symbol_indexes(debugger);
    }

    /// Leave the symbol and type indexes for the next reader to rebuild: a
    /// module unloaded, which advances neither the address space nor the
    /// symbol store's load generation. Merging every module's names is too
    /// slow to do at each stop that changed the module set.
    pub fn invalidate_symbol_indexes(&self) {
        self.indexed_at.store(NOT_INDEXED, Ordering::Release);
    }

    fn build_symbol_indexes(&self, debugger: &Target) {
        // Read first: a load during the rebuild then shows as a newer
        // generation, and the next refresh picks it up.
        let generation = debugger.symbols.load_generation();
        *self.symbols.write().unwrap() = debugger.current_symbol_index();
        *self.types.write().unwrap() = debugger.current_types_index();
        *self.dtb.write().unwrap() = debugger.current_dtb();
        self.indexed_at.store(generation, Ordering::Release);
    }

    pub fn refresh_expression_context(&self, debugger: &Target) {
        let mut variables = BTreeMap::new();
        for name in debugger.user_vars.keys() {
            if !self.registers.contains(name) {
                variables.insert(name.clone(), "Variable");
            }
        }
        for index in 0..debugger.results.len() {
            variables.insert(index.to_string(), "Result");
        }
        for var in debugger.builtin_variables() {
            variables.entry(var.name.to_string()).or_insert("Builtin");
        }
        *self.expression_variables.write().unwrap() = variables.into_iter().collect();
    }
}

/// A read-only loan of the REPL's [`Target`] to the `'static` tab completer
/// for the duration of one `read_line` ([`lend`](Self::lend)).
#[derive(Clone, Default)]
pub struct TargetLoan(Arc<Mutex<Option<LentTarget>>>);

#[derive(Clone, Copy)]
struct LentTarget(NonNull<Target>);

// SAFETY: the pointer comes from a `&Target` that stays borrowed for the whole
// loan window (`lend`), and `Target: Sync` (asserted below) makes that shared
// reference usable from any thread the editor happens to complete on.
unsafe impl Send for LentTarget {}

const _: () = {
    fn assert_sync<T: Sync>() {}
    let _ = assert_sync::<Target>;
};

impl TargetLoan {
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<LentTarget>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `f` with `target` visible to the completer. The shared borrow held
    /// for the call keeps the target alive and unmutated meanwhile.
    pub fn lend<R>(&self, target: &Target, f: impl FnOnce() -> R) -> R {
        struct Reset<'a>(&'a TargetLoan);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                *self.0.slot() = None;
            }
        }
        let _reset = Reset(self);
        *self.slot() = Some(LentTarget(NonNull::from(target)));
        f()
    }

    /// The lent target, if a loan is active. The loan's lock is held for the
    /// whole call, so `lend` cannot return (and drop the borrow) while `f`
    /// still reads the target; `f` must not call back into the loan.
    pub fn with<R>(&self, f: impl FnOnce(Option<&Target>) -> R) -> R {
        let slot = self.slot();
        match *slot {
            // SAFETY: the pointer is set only inside `lend`, from a `&Target`
            // whose borrow outlives that call, and is cleared (under this same
            // lock) before `lend` returns, also on unwind; holding the lock
            // here means the borrow stays live for the whole of `f`.
            Some(LentTarget(ptr)) => f(Some(unsafe { ptr.as_ref() })),
            None => f(None),
        }
    }
}
