use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::backend::host::VmHandle;
use crate::backend::kd::KdMemory;
use crate::base::error::{Error, Result};
use crate::base::memory::{
    CompressedPages, MemoryOps, PAGE_FILE_LOW, PAGE_SIZE, SectionViews, TranslationCache,
};
use crate::base::types::{Dtb, PhysAddr, VirtAddr};
use crate::nt::dmp::{DmpInfo, DmpMem};
use crate::nt::guest::ept::EptMemory;
use crate::nt::userdump::UserDump;

/// Guest physical memory backed by a live VM process, KD transport, or crash
/// dump. Built once at attach and shared via `Arc`; everything above (address
/// spaces, symbol loading, unwinding) reads through it.
///
/// A user-mode minidump is the exception: it captured process memory by
/// virtual address, so it serves virtual reads directly and has no physical
/// memory at all.
pub struct PhysMem {
    source: Source,
    /// The guest kernel's `InvalidPteMask`, set when a kernel is found (see
    /// [`Self::set_invalid_pte_mask`]).
    invalid_pte_mask: AtomicU64,
    /// The first bit of a software PTE's page-file number, set when a kernel
    /// is found (see [`Self::set_page_file_low`]).
    page_file_low: AtomicU32,
    /// The guest kernel's `MmPteBase`, 0 until a kernel is found (see
    /// [`Self::set_pte_self_map`]).
    pte_self_map: AtomicU64,
    /// The guest kernel's mapped-view lookup, set when a kernel is found (see
    /// [`Self::set_section_views`]).
    section_views: Mutex<Option<Arc<SectionViews>>>,
    /// The guest's memory-compression store, resolved on first use (see
    /// [`Self::set_compressed_pages`]).
    compressed_pages: StoreSlot,
    /// Pages decompressed from that store during the current halt.
    store_pages: Mutex<StorePageCache>,
    /// The target's interrupt flag, which Ctrl+C raises (see
    /// [`Self::set_interrupt_flag`]); finding the store stops on it.
    interrupt: Mutex<Arc<AtomicBool>>,
}

/// How a resolver finds the guest's memory-compression store: `None` when it
/// is not there (yet), or when the flag it is handed (Ctrl+C) stopped it.
pub type StoreResolver = Box<dyn FnMut(&AtomicBool) -> Option<CompressedPages> + Send>;

/// How long a store not found while the guest may be running goes before
/// it is looked for again.
const STORE_RETRY_WHILE_RUNNING: Duration = Duration::from_secs(1);

/// Where the guest's memory-compression store stands.
enum StoreState {
    /// No resolver here: no kernel found yet, or the resolver is running
    /// (its own reads ask for the store, and get none).
    Idle,
    /// A kernel found, and its store not yet: looked for when first needed,
    /// and again once the guest may have created it since `tried`.
    Pending {
        resolve: StoreResolver,
        tried: Option<StoreTry>,
    },
    Found(Arc<CompressedPages>),
}

/// When a resolver last found no store: in which halt, if any, and when.
struct StoreTry {
    epoch: Option<u64>,
    at: Instant,
}

impl StoreTry {
    /// Whether the guest may have created its store since this try, as of
    /// halt `epoch`: it has run since, or it may be running and a while has
    /// passed. A dump is one halt forever, so it is tried once.
    fn stale(&self, epoch: Option<u64>) -> bool {
        match epoch {
            Some(_) => epoch != self.epoch,
            None => self.at.elapsed() >= STORE_RETRY_WHILE_RUNNING,
        }
    }
}

/// The guest's memory-compression store, resolved on first use. Windows
/// creates it some time after boot, so one not found yet is looked for
/// again once the guest has run.
pub struct StoreSlot(Mutex<StoreState>);

impl StoreSlot {
    fn new() -> Self {
        Self(Mutex::new(StoreState::Idle))
    }

    fn lock(&self) -> MutexGuard<'_, StoreState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve the store with `resolve` when it is first asked for.
    pub fn set(&self, resolve: StoreResolver) {
        *self.lock() = StoreState::Pending {
            resolve,
            tried: None,
        };
    }

    /// The store, as of halt `epoch` (see [`PhysMem::halt_epoch`]):
    /// resolving it on the first call, and while it is not found, again
    /// whenever [`StoreTry::stale`]. A resolver `interrupt` stopped tried
    /// nothing. The resolver reads guest memory, which asks for the store
    /// again: it runs unlocked, and those nested calls get `None`.
    pub fn get(&self, epoch: Option<u64>, interrupt: &AtomicBool) -> Option<Arc<CompressedPages>> {
        let mut state = self.lock();
        let (mut resolve, tried) = match std::mem::replace(&mut *state, StoreState::Idle) {
            StoreState::Pending { resolve, tried }
                if tried.as_ref().is_none_or(|tried| tried.stale(epoch)) =>
            {
                (resolve, tried)
            }
            other => {
                let found = match &other {
                    StoreState::Found(pages) => Some(Arc::clone(pages)),
                    StoreState::Idle | StoreState::Pending { .. } => None,
                };
                *state = other;
                return found;
            }
        };
        drop(state);
        let found = resolve(interrupt).map(Arc::new);
        let next = match &found {
            Some(pages) => StoreState::Found(Arc::clone(pages)),
            None if interrupt.load(Ordering::Relaxed) => StoreState::Pending { resolve, tried },
            None => StoreState::Pending {
                resolve,
                tried: Some(StoreTry {
                    epoch,
                    at: Instant::now(),
                }),
            },
        };
        let mut state = self.lock();
        // A kernel found meanwhile (the guest rebooted) set its own.
        if matches!(*state, StoreState::Idle) {
            *state = next;
        }
        found
    }
}

/// How many decompressed store pages [`StorePageCache`] keeps (64 MiB)
/// before it starts over.
const STORE_PAGE_CACHE_PAGES: usize = 0x4000;

/// Pages decompressed from the memory-compression store during one halt,
/// by page-file number and page. A walk under a page table in the store
/// decompresses that table each time, and `.dump /u` walks each page
/// several times; the guest changes neither until it runs.
#[derive(Default)]
pub struct StorePageCache {
    epoch: Option<u64>,
    pages: HashMap<u64, Arc<[u8; PAGE_SIZE]>>,
}

impl StorePageCache {
    /// The page cached under `key` in halt `epoch`; none while the guest
    /// may be running.
    pub fn get(&self, epoch: Option<u64>, key: u64) -> Option<Arc<[u8; PAGE_SIZE]>> {
        if epoch.is_none() || epoch != self.epoch {
            return None;
        }
        self.pages.get(&key).cloned()
    }

    /// Cache `page` under `key` for halt `epoch`, dropping the pages of an
    /// earlier halt, or all of them once full.
    pub fn put(&mut self, epoch: Option<u64>, key: u64, page: Arc<[u8; PAGE_SIZE]>) {
        if epoch.is_none() {
            return;
        }
        if epoch != self.epoch || self.pages.len() >= STORE_PAGE_CACHE_PAGES {
            self.pages.clear();
            self.epoch = epoch;
        }
        self.pages.insert(key, page);
    }
}

/// Where [`PhysMem`] reads from. `Dmp` is boxed because it is much larger than
/// the live handle.
enum Source {
    /// Live VM RAM. Reads come straight from the host mapping; writes go
    /// through `mediated` when there is one, because poking a guest frame from
    /// the host bypasses everything the guest's memory manager knows about
    /// that page, including PTE write protection, copy-on-write, residency and
    /// dirty tracking, while a target-mediated write is serviced by the guest's own
    /// debug-memory path.
    ///
    /// Mediation needs a request/reply exchange, so it only applies while the
    /// target is halted. A write to a running guest keeps using the host
    /// mapping: it is the only mechanism left, and such a write is already
    /// best-effort because the guest may be touching the same bytes.
    Live {
        host: VmHandle,
        mediated: Option<KdMemory>,
        /// Halts of the GDB stub controlling the VM, when it is the one.
        halts: Option<Arc<HaltClock>>,
    },
    Dmp(Box<DmpMem>),
    /// A user-mode minidump's captured process memory. It is keyed by
    /// virtual address and has no physical side: every virtual read is
    /// served directly, whatever the root, and physical reads and page-table
    /// reads fail with [`Error::NoPhysicalMemory`].
    UserDump(Box<UserDump>),
    Remote(KdMemory),
    /// The guest physical memory of a partition of the Windows hypervisor
    /// that runs inside the target (a Windows Sandbox, a Hyper-V VM), read
    /// through the EPT that `eptp` roots from the target's own physical
    /// memory, `host`. Read-only: a write would bypass the guest the way a
    /// host write to a live VM does, and through another hypervisor too.
    Partition {
        host: Arc<PhysMem>,
        eptp: u64,
        mode_based: bool,
        /// The guest physical ranges the EPT maps, as `(base, len)`.
        runs: Vec<(u64, u64)>,
    },
}

/// Whether a backend that controls a live VM has it halted, and which halt
/// this is: the resume signal host memory lacks. Shared between the backend,
/// which reports every resume and halt, and [`PhysMem::halt_epoch`].
#[derive(Debug, Default)]
pub struct HaltClock {
    epoch: AtomicU64,
    running: AtomicBool,
}

impl HaltClock {
    /// Record a resume (a new epoch begins) or a halt.
    pub fn set_running(&self, running: bool) {
        if running {
            if !self.running.swap(true, Ordering::AcqRel) {
                self.epoch.fetch_add(1, Ordering::AcqRel);
            }
        } else {
            self.running.store(false, Ordering::Release);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// The current halt's epoch; `None` while the target runs.
    pub fn epoch(&self) -> Option<u64> {
        (!self.is_running()).then(|| self.epoch.load(Ordering::Acquire))
    }
}

impl PhysMem {
    /// Write `buf` at `addr` through the host mapping of a live VM's RAM,
    /// whether or not the target could service the write; `None` without a
    /// host mapping. It bypasses everything a target-mediated write does
    /// (see [`Source::Live`]), so it is for writes that mean to reach the
    /// frame itself.
    pub fn write_through_host(&self, addr: PhysAddr, buf: &[u8]) -> Option<Result<()>> {
        match &self.source {
            Source::Live { host, .. } => Some(host.write_bytes(addr, buf)),
            _ => None,
        }
    }

    fn from_source(source: Source) -> Self {
        Self {
            source,
            invalid_pte_mask: AtomicU64::new(0),
            page_file_low: AtomicU32::new(PAGE_FILE_LOW),
            pte_self_map: AtomicU64::new(0),
            section_views: Mutex::new(None),
            compressed_pages: StoreSlot::new(),
            store_pages: Mutex::default(),
            interrupt: Mutex::default(),
        }
    }

    pub fn live() -> Result<Self> {
        Ok(Self::from_source(Source::Live {
            host: VmHandle::new()?,
            mediated: None,
            halts: None,
        }))
    }

    /// Hand guest writes to the target while reads keep coming from the host
    /// mapping. A no-op for sources that have no host mapping.
    pub fn with_mediated_writes(self, memory: KdMemory) -> Self {
        match self.source {
            Source::Live { host, halts, .. } => Self::from_source(Source::Live {
                host,
                mediated: Some(memory),
                halts,
            }),
            _ => self,
        }
    }

    /// Take halts from the backend controlling the VM, so guest-derived lists
    /// can be memoized per halt. A no-op for sources that have no host
    /// mapping.
    pub fn with_halt_clock(self, clock: Arc<HaltClock>) -> Self {
        match self.source {
            Source::Live { host, mediated, .. } => Self::from_source(Source::Live {
                host,
                mediated,
                halts: Some(clock),
            }),
            _ => self,
        }
    }

    pub fn dmp(path: &Path) -> Result<Self> {
        Ok(Self::from_source(Source::Dmp(Box::new(DmpMem::open(
            path,
        )?))))
    }

    pub fn minidump(dump: UserDump) -> Self {
        Self::from_source(Source::UserDump(Box::new(dump)))
    }

    pub fn remote(memory: KdMemory) -> Self {
        Self::from_source(Source::Remote(memory))
    }

    /// The guest physical memory of a hypervisor partition: `host`'s read
    /// through the EPT `eptp` roots (with mode-based execute control when
    /// `mode_based`), whose mapped ranges are `runs`.
    pub fn partition(
        host: Arc<PhysMem>,
        eptp: u64,
        mode_based: bool,
        runs: Vec<(u64, u64)>,
    ) -> Self {
        Self::from_source(Source::Partition {
            host,
            eptp,
            mode_based,
            runs,
        })
    }

    /// Whether this is a hypervisor partition's memory (see
    /// [`Self::partition`]), which its VTL0 EPT maps: never its VTL1's.
    pub fn is_partition(&self) -> bool {
        matches!(self.source, Source::Partition { .. })
    }

    /// Whether guest memory is read through the debug target (KD) rather
    /// than from the host, one request per line or page.
    pub fn reads_through_target(&self) -> bool {
        matches!(self.source, Source::Remote(_))
    }

    /// Whether this is a crash dump, which never changes.
    pub fn is_dump(&self) -> bool {
        matches!(self.source, Source::Dmp(_) | Source::UserDump(_))
    }

    /// The user-mode minidump this reads, `None` for every kernel source.
    pub fn user_dump(&self) -> Option<&UserDump> {
        match &self.source {
            Source::UserDump(dump) => Some(dump),
            _ => None,
        }
    }

    pub fn is_user_dump(&self) -> bool {
        matches!(self.source, Source::UserDump(_))
    }

    /// Whether this reads a live VM's RAM from the host.
    /// Whether the hypervisor aborts this live VM when a debugger enables
    /// guest debugging (QEMU under HVF); see `VmHandle::guest_debug_aborts_vm`.
    pub fn guest_debug_aborts_vm(&self) -> bool {
        match &self.source {
            Source::Live { host, .. } => host.guest_debug_aborts_vm(),
            Source::Dmp(_) | Source::UserDump(_) | Source::Remote(_) | Source::Partition { .. } => {
                false
            }
        }
    }

    pub fn is_live_host(&self) -> bool {
        matches!(self.source, Source::Live { .. })
    }

    /// Record the guest kernel's `InvalidPteMask` for this boot; see
    /// [`MemoryOps::invalid_pte_mask`].
    pub fn set_invalid_pte_mask(&self, mask: u64) {
        self.invalid_pte_mask.store(mask, Ordering::Release);
    }

    /// Record where the guest kernel's software PTEs keep their page-file
    /// number; see [`MemoryOps::page_file_low`].
    pub fn set_page_file_low(&self, bit: u32) {
        self.page_file_low.store(bit, Ordering::Release);
    }

    /// Record the guest kernel's `MmPteBase`. The 512 GiB self-map it heads
    /// is kernel space that maps whichever root it is read through, so a
    /// target's virtual-memory API, which reads kernel space through its own
    /// current root, cannot serve it for another root.
    pub fn set_pte_self_map(&self, pte_base: u64) {
        self.pte_self_map.store(pte_base, Ordering::Release);
    }

    fn in_pte_self_map(&self, addr: VirtAddr) -> bool {
        let base = self.pte_self_map.load(Ordering::Acquire);
        base != 0 && addr.0.wrapping_sub(base) < 1 << 39
    }

    /// Record the guest kernel's mapped-view lookup for this boot, or `None`
    /// when its PDB lacks the layout; see [`MemoryOps::section_views`].
    pub fn set_section_views(&self, views: Option<SectionViews>) {
        *self
            .section_views
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = views.map(Arc::new);
    }

    /// The flag Ctrl+C raises for work done on this memory's behalf.
    pub fn interrupt_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(
            &self
                .interrupt
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Make `flag` the one Ctrl+C raises; the target sets its own (see
    /// [`crate::nt::target::Target::set_interrupt`]).
    pub fn set_interrupt_flag(&self, flag: Arc<AtomicBool>) {
        *self
            .interrupt
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = flag;
    }

    /// Record how to find the guest's memory-compression store for this boot:
    /// `resolve` runs the first time a page may be in the store, and again
    /// while it finds none (see [`StoreSlot::get`]); see
    /// [`MemoryOps::compressed_pages`].
    pub fn set_compressed_pages(&self, resolve: StoreResolver) {
        self.compressed_pages.set(resolve);
    }

    pub fn dmp_info(&self) -> Option<&DmpInfo> {
        match &self.source {
            Source::Dmp(d) => Some(d.info()),
            _ => None,
        }
    }

    /// Guest-physical address where RAM starts (below is firmware/MMIO):
    /// x86 QEMU/VMware: 0; aarch64 QEMU `virt`: 0x4000_0000 (1 GiB).
    pub fn ram_base(&self) -> u64 {
        match &self.source {
            Source::Live { host, .. } => host.ram_base(),
            Source::Dmp(_) | Source::UserDump(_) | Source::Remote(_) | Source::Partition { .. } => {
                0
            }
        }
    }

    /// The host mapping guest reads come from, for diagnostics. `None` for
    /// sources that are not a live VM process.
    pub fn host_mapping(&self) -> Option<String> {
        match &self.source {
            Source::Live { host, .. } => Some(host.describe()),
            Source::Dmp(_) | Source::UserDump(_) | Source::Remote(_) | Source::Partition { .. } => {
                None
            }
        }
    }

    /// Total mapped guest RAM size.
    pub fn ram_size(&self) -> u64 {
        match &self.source {
            Source::Live { host, .. } => host.ram_size(),
            Source::Partition { runs, .. } => runs.iter().map(|(_, length)| length).sum(),
            Source::Dmp(_) | Source::UserDump(_) | Source::Remote(_) => 0,
        }
    }

    /// Guest-physical RAM as `(base, len)` runs, for memory sources that know
    /// the layout (a live VM process). Empty for KD and dumps, whose callers
    /// take the runs from the guest's own `MmPhysicalMemoryBlock`.
    pub fn ram_runs(&self) -> Vec<(u64, u64)> {
        match &self.source {
            Source::Live { host, .. } => host.ram_runs(),
            Source::Partition { runs, .. } => runs.clone(),
            Source::Dmp(_) | Source::UserDump(_) | Source::Remote(_) => Vec::new(),
        }
    }

    /// Identity of the current halt, for memoizing guest-derived lists: equal
    /// values mean the guest has not run in between. A live VM process has no
    /// resume signal of its own; while KD or the GDB stub controls execution
    /// its halts serve, and while the target runs, or with nothing controlling
    /// it, this is `None` and nothing may be memoized. A dump never changes, so
    /// it is one epoch forever.
    pub fn halt_epoch(&self) -> Option<u64> {
        match &self.source {
            Source::Remote(kd) => kd.translation_cache().map(TranslationCache::halt_epoch),
            // KD bumps the epoch when the target resumes, and host reads keep
            // working while it runs: a walk then must not be memoized under
            // the new epoch and served after the next halt.
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => {
                kd.translation_cache().map(TranslationCache::halt_epoch)
            }
            Source::Live {
                halts: Some(clock), ..
            } => clock.epoch(),
            Source::Dmp(_) | Source::UserDump(_) => Some(0),
            // The partition changes only while the target runs.
            Source::Partition { host, .. } => host.halt_epoch(),
            Source::Live { .. } => None,
        }
    }
}

impl MemoryOps<PhysAddr> for PhysMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match &self.source {
            Source::Live { host, .. } => host.read_bytes(addr, buf),
            Source::Dmp(d) => d.read_bytes(addr, buf),
            Source::UserDump(_) => Err(Error::NoPhysicalMemory),
            Source::Remote(kd) => kd.read_bytes(addr, buf),
            Source::Partition {
                host,
                eptp,
                mode_based,
                ..
            } => EptMemory::new(&**host, *eptp, *mode_based).read_bytes(addr, buf),
        }
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        match &self.source {
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_bytes(addr, buf),
            // The target cannot service a request while it runs, and the host
            // mapping is the only mechanism left. Such a write is already
            // best-effort because the guest may be touching the same bytes,
            // so it stays available rather than requiring an interrupt.
            Source::Live { host, .. } => host.write_bytes(addr, buf),
            Source::Dmp(d) => d.write_bytes(addr, buf),
            Source::UserDump(_) => Err(Error::NoPhysicalMemory),
            Source::Remote(kd) => kd.write_bytes(addr, buf),
            Source::Partition {
                host,
                eptp,
                mode_based,
                ..
            } => EptMemory::new(&**host, *eptp, *mode_based).write_bytes(addr, buf),
        }
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        match &self.source {
            Source::Remote(_) if self.in_pte_self_map(addr) => None,
            // The target refuses a resident page its own access would fault
            // on, such as an ARM64 page whose access flag Windows cleared to
            // age it; the walk reads such a page's frame, and reports a page
            // nothing maps as the refusal did.
            Source::Remote(kd) => match kd.read_virtual_direct(addr, root, buf) {
                Some(Err(Error::BadVirtualAddress(_) | Error::PartialRead(_))) => None,
                result => result,
            },
            // One process, one address space: the root names nothing here.
            Source::UserDump(dump) => Some(dump.read_virtual(addr, buf)),
            // A host mapping is there to be read directly; that is the whole
            // point of selecting it.
            Source::Live { .. } | Source::Dmp(_) | Source::Partition { .. } => None,
        }
    }

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        match &self.source {
            Source::UserDump(_) => Some(Err(Error::ReadOnlyDump)),
            _ if self.in_pte_self_map(addr) => None,
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_virtual_direct(addr, root, buf),
            Source::Remote(kd) => kd.write_virtual_direct(addr, root, buf),
            Source::Live { .. } | Source::Dmp(_) | Source::Partition { .. } => None,
        }
    }

    fn can_mediate_writes(&self) -> bool {
        match &self.source {
            Source::Live {
                mediated: Some(kd), ..
            }
            | Source::Remote(kd) => kd.can_mediate_writes(),
            Source::Live { .. }
            | Source::Dmp(_)
            | Source::UserDump(_)
            | Source::Partition { .. } => false,
        }
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        match &self.source {
            Source::Remote(kd) => kd.translation_cache(),
            // Host reads are cheap enough to walk every time, and a mediated
            // write clears the target's own cache.
            Source::Live { .. }
            | Source::Dmp(_)
            | Source::UserDump(_)
            | Source::Partition { .. } => None,
        }
    }

    fn read_page_table_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match &self.source {
            Source::Remote(kd) => kd.read_page_table_bytes(addr, buf),
            Source::Live { .. }
            | Source::Dmp(_)
            | Source::UserDump(_)
            | Source::Partition { .. } => self.read_bytes(addr, buf),
        }
    }

    fn invalid_pte_mask(&self) -> u64 {
        self.invalid_pte_mask.load(Ordering::Acquire)
    }

    fn page_file_low(&self) -> u32 {
        self.page_file_low.load(Ordering::Acquire)
    }

    fn section_views(&self) -> Option<Arc<SectionViews>> {
        self.section_views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn compressed_pages(&self) -> Option<Arc<CompressedPages>> {
        self.compressed_pages
            .get(self.halt_epoch(), &self.interrupt_flag())
    }

    fn cached_store_page(&self, key: u64) -> Option<Arc<[u8; PAGE_SIZE]>> {
        self.store_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(self.halt_epoch(), key)
    }

    fn cache_store_page(&self, key: u64, page: Arc<[u8; PAGE_SIZE]>) {
        let epoch = self.halt_epoch();
        self.store_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .put(epoch, key, page);
    }
}

#[cfg(test)]
mod tests {
    use super::HaltClock;

    use crate::base::memory::store::fixture;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A page decompressed from the store is reused within a halt, and not
    /// after the guest ran, nor while it may be running.
    #[test]
    fn a_store_page_is_cached_for_one_halt_only() {
        let mut cache = super::StorePageCache::default();
        let page = Arc::new([7u8; crate::base::memory::PAGE_SIZE]);
        cache.put(Some(1), 0x2_0000_0042, Arc::clone(&page));
        assert_eq!(cache.get(Some(1), 0x2_0000_0042), Some(Arc::clone(&page)));
        assert!(cache.get(Some(1), 0x2_0000_0043).is_none());
        assert!(cache.get(Some(2), 0x2_0000_0042).is_none(), "the guest ran");
        assert!(
            cache.get(None, 0x2_0000_0042).is_none(),
            "it may be running"
        );
        cache.put(None, 0x2_0000_0044, Arc::clone(&page));
        assert!(cache.get(Some(1), 0x2_0000_0044).is_none());
        // A put in a later halt drops the earlier halt's pages.
        cache.put(Some(2), 0x2_0000_0045, page);
        assert!(cache.get(Some(2), 0x2_0000_0042).is_none());
        assert!(cache.get(Some(2), 0x2_0000_0045).is_some());
    }

    /// The resolver runs on first use and, while it finds no store (the
    /// store manager creates it after boot), again once per halt; one
    /// Ctrl+C stopped tried nothing and runs again on the next ask. A found
    /// store is kept. A read the resolver makes asks for the store again and
    /// gets none instead of deadlocking.
    #[test]
    fn a_missing_store_is_looked_for_again_once_the_guest_has_run() {
        let slot = Arc::new(super::StoreSlot::new());
        let interrupt = AtomicBool::new(false);
        assert!(slot.get(Some(0), &interrupt).is_none(), "no kernel yet");
        let runs = Arc::new(AtomicUsize::new(0));
        let nested = Arc::new(Mutex::new(None));
        let resolver = {
            let (slot, runs, nested) = (Arc::clone(&slot), Arc::clone(&runs), Arc::clone(&nested));
            Box::new(move |interrupt: &AtomicBool| {
                // No store until the third try that Ctrl+C did not stop.
                let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
                *nested.lock().unwrap() = Some(slot.get(Some(9), interrupt).is_some());
                (run >= 4 && !interrupt.load(Ordering::SeqCst)).then(|| fixture::pages(3))
            })
        };
        slot.set(resolver);
        assert!(slot.get(Some(1), &interrupt).is_none());
        assert!(
            slot.get(Some(1), &interrupt).is_none(),
            "same halt: not tried again"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(slot.get(Some(2), &interrupt).is_none());
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        interrupt.store(true, Ordering::SeqCst);
        assert!(slot.get(Some(3), &interrupt).is_none());
        interrupt.store(false, Ordering::SeqCst);
        // The interrupted try did not count: it is tried again in the same
        // halt.
        let found = slot.get(Some(3), &interrupt).map(|store| store.manager);
        assert_eq!(found, Some(crate::base::types::VirtAddr(fixture::MANAGER)));
        assert_eq!(*nested.lock().unwrap(), Some(false));
        assert!(slot.get(Some(4), &interrupt).is_some());
        assert!(slot.get(None, &interrupt).is_some());
        assert_eq!(runs.load(Ordering::SeqCst), 4, "a found store is kept");
    }

    /// A resolver set while another runs, a rebooted guest's kernel's, is
    /// the one the slot keeps.
    #[test]
    fn a_resolver_set_while_one_runs_is_kept() {
        let slot = Arc::new(super::StoreSlot::new());
        let interrupt = AtomicBool::new(false);
        let old = {
            let slot = Arc::clone(&slot);
            Box::new(move |_: &AtomicBool| {
                slot.set(Box::new(|_: &AtomicBool| Some(fixture::pages(0x5000))));
                Some(fixture::pages(3))
            })
        };
        slot.set(old);
        assert_eq!(
            slot.get(Some(1), &interrupt).map(|store| store.owner_root),
            Some(3)
        );
        assert_eq!(
            slot.get(Some(1), &interrupt).map(|store| store.owner_root),
            Some(0x5000)
        );
    }

    /// While the guest may be running there is no halt to go by: a missing
    /// store is looked for again after a while, or at the next halt.
    #[test]
    fn a_store_try_goes_stale_with_a_new_halt_or_time_while_running() {
        use std::time::{Duration, Instant};
        let recent = super::StoreTry {
            epoch: None,
            at: Instant::now(),
        };
        assert!(!recent.stale(None));
        assert!(recent.stale(Some(5)));
        let old = super::StoreTry {
            epoch: Some(5),
            at: Instant::now() - Duration::from_secs(2),
        };
        assert!(old.stale(None));
        assert!(!old.stale(Some(5)), "a halt's memory does not change");
        assert!(old.stale(Some(6)));
    }

    /// Guest lists are memoized under an epoch; one served after the guest
    /// ran would be stale.
    #[test]
    fn a_halt_clock_has_no_epoch_while_running_and_a_new_one_after() {
        let clock = HaltClock::default();
        let first = clock.epoch().expect("halted at attach");

        clock.set_running(true);
        assert_eq!(clock.epoch(), None);
        // A second report of the same run is not another resume.
        clock.set_running(true);
        clock.set_running(false);
        let second = clock.epoch().expect("halted again");
        assert_eq!(second, first + 1);

        // Halting again without running keeps the epoch.
        clock.set_running(false);
        assert_eq!(clock.epoch(), Some(second));
    }
}
