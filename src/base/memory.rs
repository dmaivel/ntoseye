use crate::arch::{Arch, MappingPermissions, TableEntry};
use crate::base::error::{Error, Result};
use crate::base::types::*;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

mod ops;
mod sections;
mod store;
mod store_tree;

pub use ops::{MemoryOps, PAGE_FILE_LOW};
pub use sections::{SectionLayout, SectionViews};
pub use store::{CompressedPages, Compression, StoreLayout};

pub const PAGE_SIZE: usize = 0x1000; // 4KiB

/// Visit a byte range in chunks that never cross a virtual-memory page.
pub fn for_each_page_chunk(
    start: VirtAddr,
    length: usize,
    mut visit: impl FnMut(usize, VirtAddr, usize),
) {
    let mut offset = 0usize;
    while offset < length {
        let address = start + offset as u64;
        let page_remaining = PAGE_SIZE - address.page_offset() as usize;
        let chunk_len = (length - offset).min(page_remaining);
        visit(offset, address, chunk_len);
        offset += chunk_len;
    }
}

/// Read a byte range page by page, preserving holes in `valid`. Unreadable
/// pages are skipped; a running-target refusal applies to the whole range.
/// A user-mode minidump captures memory at byte granularity, so a page it
/// holds only part of keeps the parts it holds.
pub fn read_page_chunks(
    start: VirtAddr,
    length: usize,
    mut read: impl FnMut(VirtAddr, &mut [u8]) -> Result<()>,
) -> Result<(Vec<u8>, Vec<bool>)> {
    let mut data = vec![0u8; length];
    let mut valid = vec![false; length];
    let mut running = Ok(());
    for_each_page_chunk(start, length, |offset, address, chunk_len| {
        if running.is_err() {
            return;
        }
        let mut from = 0usize;
        while from < chunk_len {
            match read(
                address + from as u64,
                &mut data[offset + from..offset + chunk_len],
            ) {
                Ok(()) => {
                    valid[offset + from..offset + chunk_len].fill(true);
                    break;
                }
                Err(error @ Error::TargetRunning(_)) => {
                    running = Err(error);
                    break;
                }
                // The bytes before the hole were read; read on from where
                // the capture resumes, if that is in this chunk.
                Err(Error::NotCaptured {
                    address: missing,
                    resumes,
                }) => {
                    let within = |at: VirtAddr| {
                        at.0.checked_sub(address.0)
                            .filter(|delta| *delta <= chunk_len as u64)
                            .map(|delta| delta as usize)
                    };
                    let read_to = within(missing).unwrap_or(from).max(from);
                    valid[offset + from..offset + read_to].fill(true);
                    match resumes
                        .and_then(within)
                        .filter(|next| *next > read_to && *next < chunk_len)
                    {
                        Some(next) => from = next,
                        None => break,
                    }
                }
                Err(_) => break,
            }
        }
    });
    running.map(|()| (data, valid))
}

/// The readable contents of a NUL-terminated string, without the terminator.
#[derive(Debug, PartialEq, Eq)]
pub struct TerminatedRead {
    /// Readable bytes before the terminator or the first unreadable page.
    pub bytes: Vec<u8>,
    /// The string ran into an unreadable page before its terminator.
    pub unreadable: bool,
}

/// How a [`read_terminated`] read failed.
#[derive(Debug)]
pub enum ScanFault {
    /// The page is unreadable: the scan ends with the bytes before it, or
    /// with this error when there are none.
    Unreadable(Error),
    /// The scan ends with this error, whatever it has read.
    Fatal(Error),
}

/// Scan the string of `unit`-byte characters at `addr`, at most `max_bytes`
/// long, for its first all-zero unit, reading a page at a time with `read`.
/// A unit split by a page boundary is joined before the check, and the
/// result holds whole units only. Addresses wrap at the top of the address
/// space; `read` decides whether that is an error. `unit` must not be zero.
pub fn read_terminated(
    addr: VirtAddr,
    max_bytes: usize,
    unit: usize,
    mut read: impl FnMut(VirtAddr, &mut [u8]) -> std::result::Result<(), ScanFault>,
) -> Result<TerminatedRead> {
    let mut bytes = Vec::with_capacity(max_bytes.min(PAGE_SIZE));
    let mut unreadable = false;
    while bytes.len() < max_bytes {
        let start = bytes.len();
        let current = addr + start as u64;
        let page_remaining = PAGE_SIZE - current.page_offset() as usize;
        bytes.resize(start + page_remaining.min(max_bytes - start), 0);
        match read(current, &mut bytes[start..]) {
            Ok(()) => {}
            Err(ScanFault::Unreadable(error)) if start == 0 => return Err(error),
            Err(ScanFault::Unreadable(_)) => {
                bytes.truncate(start);
                unreadable = true;
                break;
            }
            Err(ScanFault::Fatal(error)) => return Err(error),
        }
        let complete_units = bytes.len() / unit;
        if let Some(index) = (start / unit..complete_units).find(|&index| {
            bytes[index * unit..(index + 1) * unit]
                .iter()
                .all(|&b| b == 0)
        }) {
            bytes.truncate(index * unit);
            return Ok(TerminatedRead {
                bytes,
                unreadable: false,
            });
        }
    }
    bytes.truncate(bytes.len() - bytes.len() % unit);
    Ok(TerminatedRead { bytes, unreadable })
}

/// Offsets of every occurrence of `pattern` in `haystack`, overlapping ones
/// included. `pattern` must not be empty. A search reads up to 1 GiB, so this
/// uses `memmem`'s vectorized search rather than comparing a window at every
/// byte, which was most of the time `s` took.
pub fn pattern_offsets<'a>(
    haystack: &'a [u8],
    pattern: &'a [u8],
) -> impl Iterator<Item = usize> + 'a {
    let finder = memchr::memmem::Finder::new(pattern);
    let mut from = 0;
    std::iter::from_fn(move || {
        let at = from + finder.find(haystack.get(from..)?)?;
        // On from the next byte, not past the match, so that overlapping
        // occurrences are found too.
        from = at + 1;
        Some(at)
    })
}

/// Sentinel DTB: `AddressSpace` skips page-table translation and treats
/// virtual addresses as physical. Used by triage dumps, which only contain
/// captured virtual memory regions.
pub const DTB_IDENTITY: Dtb = u64::MAX;

/// Page translations, and pages found unmapped, remembered across
/// [`AddressSpace`] instances, which are created per read, for as long as
/// the target's page tables cannot change.
/// Owned by a backend that knows when that is: a KD target clears it on
/// every resume and write.
///
/// It also carries the target's halt epoch: a counter the owning backend
/// advances on every resume, so guest-derived lists (processes, modules,
/// drivers) memoized during one halt are dropped once the target has run.
/// Writes clear translations but do not advance the epoch: a debugger poke
/// (breakpoint install) cannot relink kernel lists.
#[derive(Default)]
pub struct TranslationCache {
    pages: Mutex<HashMap<(Dtb, u64), Option<Translation>>>,
    halt_epoch: AtomicU64,
}

impl TranslationCache {
    fn pages(&self) -> MutexGuard<'_, HashMap<(Dtb, u64), Option<Translation>>> {
        self.pages.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn get(&self, key: (Dtb, u64)) -> Option<Option<Translation>> {
        self.pages().get(&key).copied()
    }

    fn insert(&self, key: (Dtb, u64), translation: Option<Translation>) {
        self.pages().insert(key, translation);
    }

    pub fn clear(&self) {
        self.pages().clear();
    }

    /// Drop translations and start a new halt epoch; called when the target
    /// resumes.
    pub fn resume(&self) {
        self.clear();
        self.halt_epoch.fetch_add(1, Ordering::Relaxed);
    }

    pub fn halt_epoch(&self) -> u64 {
        self.halt_epoch.load(Ordering::Relaxed)
    }
}

/// One page-table entry a walk read.
#[derive(Clone, Copy)]
pub struct WalkStep {
    pub level: PageTableLevel,
    /// Where the entry sits in physical memory.
    pub address: PhysAddr,
    pub entry: PageTableEntry,
}

/// Where a page table's entries are read from: its frame, or, for a table
/// page the guest compressed into its memory-compression store, a copy.
enum TablePage {
    Frame(PhysAddr),
    Stored(Box<[u8; PAGE_SIZE]>),
}

/// Entry `index` of the table page `page`.
fn table_entry(page: &[u8; PAGE_SIZE], index: usize) -> PageTableEntry {
    let at = index * 8;
    PageTableEntry(u64::from_le_bytes(
        page[at..at + 8].try_into().expect("8-byte entry"),
    ))
}

pub struct AddressSpace<'a, B: MemoryOps<PhysAddr>> {
    backend: &'a B,
    dtb: Dtb,
    /// The root kernel VAs walk where the architecture gives them one of
    /// their own (AArch64's TTBR1, with `dtb` the TTBR0 of the user half).
    /// Unused on AMD64, where one CR3 covers both halves.
    kernel_dtb: Dtb,
    arch: Arch,
}

#[derive(Clone, Copy)]
pub struct Translation {
    pub address: PhysAddr,
    pub large: bool,
    pub user: bool,
    /// Effective execute-never for the selected address-space half: AMD64 NX,
    /// AArch64 PXN for TTBR1 addresses, or AArch64 UXN for TTBR0 addresses.
    pub nx: bool,
    /// The AArch64 mapping descriptor's UXN. Always `false` on AMD64.
    pub uxn: bool,
    pub residency: Residency,
}

/// Whether the page tables map a translated page, or where its frame was
/// found instead. A frame they do not map is readable, never written: the
/// kernel may repurpose it or read it back from disk, and the edit would
/// vanish or land somewhere unrelated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residency {
    Mapped,
    /// The leaf is a transition PTE: the frame is on the standby or modified
    /// list.
    Transition,
    /// The page tables do not map it; the frame is the one the page's
    /// section PTE holds (see [`SectionViews`]).
    Section,
}

impl Translation {
    /// The same mapping relocated to `va` within its page.
    fn at_offset(mut self, va: VirtAddr) -> Self {
        self.address = (self.address & !(PAGE_SIZE as u64 - 1)) | va.page_offset();
        self
    }

    /// A page or block the tables map at `address`, with the access they
    /// grant.
    const fn mapped(address: PhysAddr, large: bool, permissions: MappingPermissions) -> Self {
        Self {
            address,
            large,
            user: permissions.user,
            nx: permissions.nx,
            uxn: permissions.uxn,
            residency: Residency::Mapped,
        }
    }

    /// `va` itself, as an identity root (a physical address space) maps it.
    const fn identity(va: VirtAddr) -> Self {
        Self {
            address: va.0,
            large: false,
            user: false,
            nx: false,
            uxn: false,
            residency: Residency::Mapped,
        }
    }

    /// A leaf whose page is resident but not mapped. The protection bits of a
    /// software PTE describe the *future* mapping, not a current one, so none
    /// are claimed: the frame is readable and nothing else.
    pub const fn new_transition(pte: PageTableEntry, va: VirtAddr) -> Self {
        Self {
            address: pte.page_frame() + va.page_offset(),
            large: false,
            user: false,
            nx: false,
            uxn: false,
            residency: Residency::Transition,
        }
    }

    /// A page the page tables do not map, read from the frame its section
    /// PTE holds. Like a transition page, only readability is claimed.
    pub const fn new_section(frame: PhysAddr, va: VirtAddr) -> Self {
        Self {
            address: frame + va.page_offset(),
            large: false,
            user: false,
            nx: false,
            uxn: false,
            residency: Residency::Section,
        }
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    /// AMD64 address space: one CR3 at `dtb` covers both halves.
    pub fn new_amd64(backend: &'a B, dtb: Dtb) -> Self {
        Self::for_arch(backend, dtb, dtb, Arch::Amd64)
    }

    /// The page-table root this space walks (TTBR0 on AArch64).
    pub fn dtb(&self) -> Dtb {
        self.dtb
    }

    /// The architecture whose page tables and pointers this space reads.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The kernel pointer at `va`, [`Arch::pointer_size`] bytes wide.
    pub fn read_pointer(&self, va: VirtAddr) -> Result<VirtAddr> {
        let mut bytes = [0u8; 8];
        let size = self.arch.pointer_size() as usize;
        self.read_bytes(va, &mut bytes[..size])?;
        Ok(self.arch.decode_pointer(&bytes))
    }

    /// AArch64 address space with separate TTBR0 (user) and TTBR1 (kernel)
    /// roots; the walk selects the root from the VA's bit 55.
    pub fn new_arm64(backend: &'a B, ttbr0: Dtb, ttbr1: Dtb) -> Self {
        Self::for_arch(backend, ttbr0, ttbr1, Arch::Arm64)
    }

    /// The address space rooted at `dtb` for `arch`. Kernel VAs walk
    /// `kernel_dtb` where the architecture gives them a root of their own
    /// (AArch64's TTBR1); one AMD64 CR3 covers both halves.
    pub fn for_arch(backend: &'a B, dtb: Dtb, kernel_dtb: Dtb, arch: Arch) -> Self {
        Self {
            backend,
            dtb,
            kernel_dtb,
            arch,
        }
    }

    fn read_pt_entry(&self, address: PhysAddr) -> Result<Option<PageTableEntry>> {
        let mut entry = [0u8; 8];
        match self.backend.read_page_table_bytes(address, &mut entry) {
            Ok(()) => Ok(Some(PageTableEntry(u64::from_le_bytes(entry)))),
            Err(Error::BadPhysicalAddress(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Page-table root that maps `va`.
    fn root_for(&self, va: VirtAddr) -> Dtb {
        let paging = self.arch.paging();
        if paging.separate_kernel_root() && paging.is_kernel_address(va) {
            self.kernel_dtb
        } else {
            self.dtb
        }
    }

    pub fn virt_to_phys(&self, va: VirtAddr) -> Result<Option<Translation>> {
        let Some(cache) = self.backend.translation_cache() else {
            return self.walk(va);
        };
        let key = (self.root_for(va), va.0 >> PAGE_SHIFT);
        if let Some(translation) = cache.get(key) {
            return Ok(translation.map(|translation| translation.at_offset(va)));
        }
        let translation = self.walk(va)?;
        cache.insert(key, translation);
        Ok(translation)
    }

    /// Visit the present pages of `[start, end)`, reading each page table
    /// once and nothing under an absent entry, so a sparse range of
    /// terabytes costs only the tables that exist. `visit(va, physical,
    /// length)` is called per 4 KiB page, and once per large or huge page
    /// (clipped to the range); `ControlFlow::Break` ends the walk. Pages that
    /// are not valid (transition, paged out) are not visited.
    pub fn for_each_present_page(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        mut visit: impl FnMut(VirtAddr, PhysAddr, u64) -> ControlFlow<()>,
    ) -> Result<()> {
        if start.0 >= end.0 {
            return Ok(());
        }
        if self.dtb == DTB_IDENTITY {
            let _ = visit(start, start.0, end.0 - start.0);
            return Ok(());
        }
        // The root indexes the low `bits` of an address, and the upper half's
        // addresses are sign-extended from the top one.
        let bits = self.arch.paging().levels()[0].shift() + 9;
        let half = if start.0 & (1 << (bits - 1)) != 0 {
            !0 << bits
        } else {
            0
        };
        let _ = self.visit_table(
            TablePage::Frame(self.root_for(start)),
            0,
            half,
            start.0,
            end.0,
            &mut visit,
            &mut None::<fn(VirtAddr, PageTableEntry)>,
        )?;
        Ok(())
    }

    /// Each non-present, non-zero PTE-level entry that maps a page in
    /// `[start, end)`, with the address of its page: pages that are paged
    /// out or otherwise not in memory. Absent tables are skipped whole,
    /// except ones the guest trimmed: in transition, or in the
    /// memory-compression store.
    pub fn for_each_absent_pte(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        visit: impl FnMut(VirtAddr, PageTableEntry),
    ) -> Result<()> {
        if start.0 >= end.0 || self.dtb == DTB_IDENTITY {
            return Ok(());
        }
        let bits = self.arch.paging().levels()[0].shift() + 9;
        let half = if start.0 & (1 << (bits - 1)) != 0 {
            !0 << bits
        } else {
            0
        };
        let _ = self.visit_table(
            TablePage::Frame(self.root_for(start)),
            0,
            half,
            start.0,
            end.0,
            &mut |_, _, _| ControlFlow::Continue(()),
            &mut Some(visit),
        )?;
        Ok(())
    }

    /// One table of [`Self::for_each_present_page`], `depth` levels below
    /// the root, covering from `base`; entries outside `[start, end)` are
    /// skipped. With `absent`, it is handed each non-present PTE-level
    /// entry, and tables the guest trimmed are visited too
    /// ([`Self::absent_table`]).
    #[allow(clippy::too_many_arguments)]
    fn visit_table(
        &self,
        table: TablePage,
        depth: usize,
        base: u64,
        start: u64,
        end: u64,
        visit: &mut impl FnMut(VirtAddr, PhysAddr, u64) -> ControlFlow<()>,
        absent: &mut Option<impl FnMut(VirtAddr, PageTableEntry)>,
    ) -> Result<ControlFlow<()>> {
        let paging = self.arch.paging();
        let level = paging.levels()[depth];
        let shift = level.shift();
        let span = 1u64 << shift;
        let mut frame = [0u8; PAGE_SIZE];
        let entries = match &table {
            TablePage::Frame(address) => {
                match self.backend.read_page_table_bytes(*address, &mut frame) {
                    Ok(()) => &frame,
                    Err(Error::BadPhysicalAddress(_)) => return Ok(ControlFlow::Continue(())),
                    Err(error) => return Err(error),
                }
            }
            TablePage::Stored(page) => &**page,
        };
        let first = (start.max(base) - base) >> shift;
        let last = ((end - 1).min(base + ((span << 9) - 1)) - base) >> shift;
        for index in first..=last {
            let entry = table_entry(entries, index as usize);
            let entry_base = base + index * span;
            let flow = match paging.decode_entry(level, entry) {
                TableEntry::Absent => {
                    let Some(absent_entry) = absent.as_mut() else {
                        continue;
                    };
                    if level == PageTableLevel::Pte {
                        if entry.0 != 0 {
                            absent_entry(VirtAddr(entry_base), entry);
                        }
                        continue;
                    }
                    let Some(page) = self.absent_table(entry) else {
                        continue;
                    };
                    self.visit_table(page, depth + 1, entry_base, start, end, visit, absent)?
                }
                TableEntry::Leaf(frame) => {
                    let from = entry_base.max(start);
                    let to = (entry_base + (span - 1)).min(end - 1);
                    visit(VirtAddr(from), frame + (from - entry_base), to - from + 1)
                }
                TableEntry::Table(next) => self.visit_table(
                    TablePage::Frame(next),
                    depth + 1,
                    entry_base,
                    start,
                    end,
                    visit,
                    absent,
                )?,
            };
            if flow.is_break() {
                return Ok(flow);
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    fn walk(&self, va: VirtAddr) -> Result<Option<Translation>> {
        if self.dtb == DTB_IDENTITY {
            return Ok(Some(Translation::identity(va)));
        }
        match self.walk_tables(va, |_| {})? {
            Walked::Mapped(translation) => Ok(Some(translation)),
            Walked::Unmapped(leaf) => Ok(self.section_page(va, leaf)),
        }
    }

    /// The translation of `va` (uncached), with the entries its walk read,
    /// root first.
    pub fn walk_steps(&self, va: VirtAddr) -> Result<(Vec<WalkStep>, Option<Translation>)> {
        if self.dtb == DTB_IDENTITY {
            return Ok((Vec::new(), Some(Translation::identity(va))));
        }
        let mut steps = Vec::with_capacity(PageTableLevel::ALL.len());
        let translation = match self.walk_tables(va, |step| steps.push(step))? {
            Walked::Mapped(translation) => Some(translation),
            Walked::Unmapped(leaf) => self.section_page(va, leaf),
        };
        Ok((steps, translation))
    }

    /// Walk the tables for `va`, handing `on_step` each entry read from a
    /// table's frame; a table read from the memory-compression store has
    /// none, and its entries are not handed on. A table the guest trimmed
    /// is read where it is ([`Self::absent_table`]).
    fn walk_tables(&self, va: VirtAddr, mut on_step: impl FnMut(WalkStep)) -> Result<Walked> {
        let paging = self.arch.paging();
        let mut table = TablePage::Frame(self.root_for(va));
        let mut path = [PageTableEntry(0); PageTableLevel::ALL.len()];
        for (depth, &level) in paging.levels().iter().enumerate() {
            let shift = level.shift();
            let index = (va.0 >> shift) & PT_INDEX_MASK;
            let entry = match &table {
                TablePage::Frame(frame) => {
                    let address = frame + 8 * index;
                    let Some(entry) = self.read_pt_entry(address)? else {
                        return Ok(Walked::Unmapped(None));
                    };
                    on_step(WalkStep {
                        level,
                        address,
                        entry,
                    });
                    entry
                }
                TablePage::Stored(page) => table_entry(page, index as usize),
            };
            path[depth] = entry;
            match paging.decode_entry(level, entry) {
                TableEntry::Table(next) => table = TablePage::Frame(next),
                TableEntry::Leaf(frame) => {
                    let permissions = paging.mapping_permissions(&path[..=depth], va);
                    let offset = va.0 & ((1u64 << shift) - 1);
                    return Ok(Walked::Mapped(Translation::mapped(
                        frame + offset,
                        level != PageTableLevel::Pte,
                        permissions,
                    )));
                }
                TableEntry::Absent if level != PageTableLevel::Pte => {
                    match self.absent_table(entry) {
                        Some(page) => table = page,
                        None => return Ok(Walked::Unmapped(None)),
                    }
                }
                TableEntry::Absent => {
                    // A working-set trim leaves the frame in memory with the
                    // valid bit clear. The kernel's own debug-memory path
                    // reads those, so refusing them here would report memory
                    // as gone that the target can still show. ARM64's
                    // software PTEs lay out valid, prototype, transition and
                    // the frame in the bits AMD64's do.
                    if entry.is_transition() {
                        let pte = entry.unswizzled(self.backend.invalid_pte_mask());
                        return Ok(Walked::Mapped(Translation::new_transition(pte, va)));
                    }
                    return Ok(Walked::Unmapped(Some(entry)));
                }
            }
        }
        // The last level decodes no table.
        Ok(Walked::Unmapped(None))
    }

    /// A user page of a mapped view that the tables do not map, read from
    /// the frame its section PTE holds when that page is in memory (see
    /// [`SectionViews`]). `leaf` is the page's PTE, `None` when a table above
    /// it is absent.
    fn section_page(&self, va: VirtAddr, leaf: Option<PageTableEntry>) -> Option<Translation> {
        // Views are mapped in a process's user half only.
        let paging = self.arch.paging();
        if paging.is_kernel_address(va) {
            return None;
        }
        let views = self.backend.section_views()?;
        let from_vad = || views.prototype_pte(self, self.dtb, va);
        let prototype = match leaf {
            None => from_vad(),
            Some(pte) if pte.0 == 0 => from_vad(),
            Some(pte) if pte.is_prototype() => pte.prototype_address().or_else(from_vad),
            // A page-file PTE: the process's own copy of the page, paged out.
            Some(_) => None,
        }?;
        let pte = PageTableEntry(self.read::<u64>(prototype).ok()?);
        let valid = match paging.decode_entry(PageTableLevel::Pte, pte) {
            TableEntry::Leaf(frame) => Some(frame),
            TableEntry::Absent | TableEntry::Table(_) => None,
        };
        let frame = valid.or_else(|| {
            pte.is_transition()
                .then(|| pte.unswizzled(self.backend.invalid_pte_mask()).page_frame())
        })?;
        Some(Translation::new_section(frame, va))
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    /// Whether the committed user page `va`, which nothing in memory backs,
    /// holds zeros because it was never touched: for `private` memory, its
    /// PTE is a demand-zero one or there is none (no table, or zero); for a
    /// view, the section PTE the page maps is a demand-zero one. A page in
    /// the page file, or a view's page in its file, is not.
    pub fn page_is_demand_zero(&self, va: VirtAddr, private: bool) -> bool {
        if self.dtb == DTB_IDENTITY || self.arch.paging().is_kernel_address(va) {
            return false;
        }
        let leaf = match self.walk_tables(va, |_| {}) {
            Ok(Walked::Unmapped(leaf)) => leaf,
            Ok(Walked::Mapped(_)) | Err(_) => return false,
        };
        let mask = self.backend.invalid_pte_mask();
        let low = self.backend.page_file_low();
        if private {
            return leaf.is_none_or(|pte| pte.0 == 0 || pte.unswizzled(mask).is_demand_zero(low));
        }
        let Some(views) = self.backend.section_views() else {
            return false;
        };
        let from_vad = || views.prototype_pte(self, self.dtb, va);
        let prototype = match leaf {
            None => from_vad(),
            Some(pte) if pte.0 == 0 => from_vad(),
            Some(pte) if pte.is_prototype() => pte.prototype_address().or_else(from_vad),
            Some(_) => None,
        };
        prototype
            .and_then(|address| self.read::<u64>(address).ok())
            .is_some_and(|pte| PageTableEntry(pte).unswizzled(mask).is_demand_zero(low))
    }
}

thread_local! {
    /// Set while a page is read from the compression store, whose own reads
    /// must not go back to the store.
    static IN_STORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    /// Whether the page at `va` is in the guest's memory-compression store
    /// and decompresses: the page tables leave it unmapped, and a read
    /// takes it from the store.
    pub fn page_is_compressed(&self, va: VirtAddr) -> bool {
        matches!(self.compressed_page(va), Some(Ok(_)))
    }

    /// Why the page at `va` is not in memory, as its page tables say; `None`
    /// when it is (mapped, in transition, or a view's page in memory).
    pub fn non_resident(&self, va: VirtAddr) -> Option<NonResident> {
        if self.dtb == DTB_IDENTITY {
            return None;
        }
        let mut last = None;
        let leaf = match self.walk_tables(va, |step| last = Some(step)).ok()? {
            Walked::Mapped(_) => return None,
            Walked::Unmapped(leaf) if self.section_page(va, leaf).is_some() => return None,
            Walked::Unmapped(leaf) => leaf,
        };
        if let Some(pte) = leaf {
            return Some(NonResident {
                table: None,
                place: self.place_of(pte, true),
            });
        }
        // The walk stopped above the PTE: at an entry that is not present,
        // or at one whose table does not read.
        let step = last?;
        let place = match self.arch.paging().decode_entry(step.level, step.entry) {
            TableEntry::Absent => match self.place_of(step.entry, false) {
                // The table read from the store; what stopped the walk is
                // below it, in entries no step reported.
                Place::Store { problem: None, .. } => Place::Unmapped,
                place => place,
            },
            TableEntry::Table(_) | TableEntry::Leaf(_) => Place::Unreadable,
        };
        Some(NonResident {
            table: Some(step.level),
            place,
        })
    }

    /// Where the non-present `entry` puts its page (`leaf`) or its table.
    fn place_of(&self, entry: PageTableEntry, leaf: bool) -> Place {
        let unswizzled = entry.unswizzled(self.backend.invalid_pte_mask());
        let low = self.backend.page_file_low();
        let (file, offset) = unswizzled.page_file_location(low);
        if unswizzled.0 == 0 || (!leaf && (unswizzled.is_prototype() || offset == 0)) {
            return Place::Unmapped;
        }
        if unswizzled.is_prototype() {
            return Place::Prototype;
        }
        if unswizzled.is_demand_zero(low) {
            return Place::DemandZero;
        }
        match self.backend.compressed_pages() {
            Some(store) if store.page_file == file => Place::Store {
                offset,
                problem: match self.stored_page(entry) {
                    Some(Ok(_)) => None,
                    Some(Err(error)) => Some(error.to_string()),
                    None => Some("the store's own reads do not use it".into()),
                },
            },
            _ => Place::PageFile { file, offset },
        }
    }

    /// The page at `va` from the guest's memory-compression store, when the
    /// page tables leave it unmapped with a PTE in the store's page file.
    fn compressed_page(&self, va: VirtAddr) -> Option<Result<Box<[u8; PAGE_SIZE]>>> {
        let Ok(Walked::Unmapped(Some(pte))) = self.walk_tables(va, |_| {}) else {
            return None;
        };
        self.stored_page(pte)
    }

    /// Where the table a non-present table entry `entry` names is: its frame
    /// when the guest trimmed the table and it is in transition, still in
    /// memory; a copy from the memory-compression store when it is there.
    fn absent_table(&self, entry: PageTableEntry) -> Option<TablePage> {
        if entry.is_transition() {
            let entry = entry.unswizzled(self.backend.invalid_pte_mask());
            return Some(TablePage::Frame(entry.page_frame()));
        }
        self.stored_page(entry)?.ok().map(TablePage::Stored)
    }

    /// The page whose non-present PTE or table entry is `entry`, from the
    /// guest's memory-compression store when `entry` is in its page file.
    /// The store's own reads do not come back here.
    fn stored_page(&self, entry: PageTableEntry) -> Option<Result<Box<[u8; PAGE_SIZE]>>> {
        // Only a page-file entry (software, with a page-file offset) can be
        // in the store; anything else does not need the store resolved.
        if IN_STORE.get()
            || entry.is_present()
            || entry.is_prototype()
            || entry.is_transition()
            || entry.0 >> 32 == 0
        {
            return None;
        }
        let store = self.backend.compressed_pages()?;
        let (file, offset) = entry
            .unswizzled(self.backend.invalid_pte_mask())
            .page_file_location(self.backend.page_file_low());
        let key = u64::from(file) << 32 | u64::from(offset);
        if let Some(page) = self.backend.cached_store_page(key) {
            return Some(Ok(page));
        }
        let mut page = Box::new([0u8; PAGE_SIZE]);
        IN_STORE.set(true);
        let result = store.read(self, entry, &mut page);
        IN_STORE.set(false);
        if let Some(Ok(())) = result {
            self.backend.cache_store_page(key, &page);
        }
        Some(result?.map(|()| page))
    }
}

/// Why a page is not in memory, as its page tables say
/// ([`AddressSpace::non_resident`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResident {
    /// The level whose entry names the page table that is not in memory;
    /// `None` when the page itself is not.
    pub table: Option<PageTableLevel>,
    pub place: Place,
}

/// Where a page, or a page table, that is not in memory is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// Nothing maps it: no page table, or a zero entry.
    Unmapped,
    /// Committed but never touched; it reads as zeros once touched.
    DemandZero,
    /// A view's page this process has not touched, and the section's own
    /// PTE leaves it out of memory.
    Prototype,
    /// In paging file `file`, at page `offset`.
    PageFile { file: u8, offset: u32 },
    /// In the memory-compression store, at page `offset` of its page file:
    /// read from there, or, with `problem`, not.
    Store {
        offset: u32,
        problem: Option<String>,
    },
    /// Its entry is present, but its frame does not read (a dump without
    /// it).
    Unreadable,
}

impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmapped => write!(f, "not mapped"),
            Self::DemandZero => write!(f, "committed but never touched (demand zero)"),
            Self::Prototype => write!(f, "a view's page that is not in memory"),
            Self::PageFile { file, offset } => write!(f, "in page file {file} at page {offset:#x}"),
            Self::Store {
                offset,
                problem: None,
            } => write!(
                f,
                "compressed in the memory-compression store (page {offset:#x}); reads decompress it"
            ),
            Self::Store {
                offset,
                problem: Some(problem),
            } => write!(
                f,
                "in the memory-compression store (page {offset:#x}), but it does not decode: {problem}"
            ),
            Self::Unreadable => write!(f, "not in memory"),
        }
    }
}

impl std::fmt::Display for NonResident {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.table, &self.place) {
            (None, place) | (Some(_), place @ Place::Unmapped) => write!(f, "{place}"),
            (Some(level), place) => {
                write!(f, "its page table, which its {level} names, is {place}")
            }
        }
    }
}

/// Where a table walk ended.
enum Walked {
    Mapped(Translation),
    /// Nothing maps the page. The leaf PTE, when its table exists, says why.
    Unmapped(Option<PageTableEntry>),
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        if let Some(result) = self
            .backend
            .read_virtual_direct(addr, self.root_for(addr), buf)
        {
            return result;
        }
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None if let Some(Ok(page)) = self.compressed_page(curr_vaddr) => {
                    let start = curr_vaddr.page_offset() as usize;
                    let chunk_size = (buf.len() - offset).min(PAGE_SIZE - start);
                    buf[offset..offset + chunk_size]
                        .copy_from_slice(&page[start..start + chunk_size]);
                    offset += chunk_size;
                    continue;
                }
                None if offset > 0 => return Err(Error::PartialRead(offset)),
                None => return Err(Error::BadVirtualAddress(curr_vaddr)),
            };

            let bytes_available = PAGE_SIZE - curr_vaddr.page_offset() as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .read_bytes(translation.address, &mut buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        // A target that can service the write itself refuses an address it
        // will not write, where the page walk below reaches whatever frame is
        // mapped and reports nothing. Neither preserves write protection or
        // copy-on-write; see `KdBackend::write_virtual_direct`.
        if let Some(result) = self
            .backend
            .write_virtual_direct(addr, self.root_for(addr), buf)
        {
            return result;
        }
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None => {
                    if offset > 0 {
                        return Err(Error::PartialWrite(offset));
                    } else {
                        return Err(Error::BadVirtualAddress(curr_vaddr));
                    }
                }
            };
            // Not mapped here, so the kernel may repurpose the frame or read
            // it back from disk, and the edit would vanish or land somewhere
            // unrelated.
            let unmapped = match translation.residency {
                Residency::Mapped => None,
                Residency::Transition => Some("transition PTE"),
                Residency::Section => Some("a section's page this process has not touched"),
            };
            if let Some(reason) = unmapped {
                if offset > 0 {
                    return Err(Error::PartialWrite(offset));
                }
                return Err(Error::DebugInfo(format!(
                    "{curr_vaddr:#x} is resident but not mapped ({reason}); \
                     it cannot be written until the target faults it back in"
                )));
            }

            let bytes_available = PAGE_SIZE - curr_vaddr.page_offset() as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .write_bytes(translation.address, &buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct FakePhysMem {
        data: Vec<u8>,
        invalid_pte_mask: u64,
    }

    impl MemoryOps<PhysAddr> for FakePhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let start = addr as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(Error::BadPhysicalAddress(addr));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(0))
        }

        fn invalid_pte_mask(&self) -> u64 {
            self.invalid_pte_mask
        }
    }

    /// AMD64 page tables mapping one VA, with `leaf` as the final PTE.
    fn amd64_space(leaf: u64) -> (FakePhysMem, VirtAddr) {
        let va = VirtAddr(0x1_0000);
        let mut data = vec![0u8; 0x7000];
        for (table, next, index) in [
            (0x1000u64, 0x2000u64, va.pml4_index()),
            (0x2000, 0x3000, va.pdpt_index()),
            (0x3000, 0x4000, va.pd_index()),
        ] {
            let at = table as usize + index * 8;
            data[at..at + 8].copy_from_slice(&(next | 0b111).to_le_bytes());
        }
        let at = 0x4000 + va.pt_index() * 8;
        data[at..at + 8].copy_from_slice(&leaf.to_le_bytes());
        data[0x5000..0x5008].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        (
            FakePhysMem {
                data,
                invalid_pte_mask: 0,
            },
            va,
        )
    }

    #[test]
    fn absent_pte_walk_reports_non_present_ptes_in_range_only() {
        // Kernel half: PML4[0x1f0] -> PDPT at 0x2000 -> PD at 0x3000. PD[0]
        // -> PT at 0x4000: PTE 2 present, PTE 3 in transition, PTE 5 in a
        // page file, PTE 6 zero. PD[1] is a non-present table entry, which
        // maps no page itself.
        let mut data = vec![0u8; 0x5000];
        let mut put = |table: usize, index: usize, value: u64| {
            data[table + index * 8..table + index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(0x1000, 0x1f0, 0x2000 | 0b11);
        put(0x2000, 0, 0x3000 | 0b11);
        put(0x3000, 0, 0x4000 | 0b11);
        put(0x3000, 1, 0x0000_0012_0000_2080);
        put(0x4000, 2, 0x9000 | 0b11);
        put(0x4000, 3, 0xa000 | (1 << 11));
        put(0x4000, 5, 0x0000_00ab_0000_2080);
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        let base = 0xffff_f800_0000_0000u64;
        let absent = |start: u64, end: u64| {
            let mut visits = Vec::new();
            space
                .for_each_absent_pte(VirtAddr(base + start), VirtAddr(base + end), |va, pte| {
                    visits.push((va.0 - base, pte.0));
                })
                .unwrap();
            visits
        };
        assert_eq!(
            absent(0, 0x4000_0000),
            [
                (0x3000, 0xa000 | (1 << 11)),
                (0x5000, 0x0000_00ab_0000_2080)
            ]
        );
        assert_eq!(absent(0x4000, 0x5000), []);
        assert_eq!(absent(0x5000, 0x6000), [(0x5000, 0x0000_00ab_0000_2080)]);
    }

    /// Physical memory of a guest that compressed pages, a page table among
    /// them, into its store.
    struct StoredPhysMem {
        memory: FakePhysMem,
        store: Arc<CompressedPages>,
        page_file_low: u32,
    }

    impl MemoryOps<PhysAddr> for StoredPhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.memory.read_bytes(addr, buf)
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            self.memory.write_bytes(addr, buf)
        }

        fn compressed_pages(&self) -> Option<Arc<CompressedPages>> {
            Some(Arc::clone(&self.store))
        }

        fn page_file_low(&self) -> u32 {
            self.page_file_low
        }
    }

    /// The table at 1 GiB, in the store under key 0x2000_0042 (page file 2,
    /// offset 0x42), whose entry 5 is `stored`, the PTE naming that same
    /// key: the PDE names it as the table, entry 5 as the page. A kernel
    /// with `page_file_low` reads the page-file number at that bit.
    fn stored_table(stored: u64, page_file_low: u32) -> StoredPhysMem {
        let mut original = vec![0u8; PAGE_SIZE];
        original[40..48].copy_from_slice(&stored.to_le_bytes());
        let data = lz4_flex::block::compress(&original);
        let leaf = |key: u32, value: u32| {
            let mut node = vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            node.extend_from_slice(&key.to_le_bytes());
            node.extend_from_slice(&value.to_le_bytes());
            node
        };
        let q = |value: u64| value.to_le_bytes().to_vec();
        let d = |value: u32| value.to_le_bytes().to_vec();
        let (manager, store, owner) = (0x100_000u64, 0x200_000u64, 0xffff_8000_0000_1000u64);
        let st = store + 0x50;
        let (key, region_key, record_key) = (0x2000_0042u32, 1 << 8 | 2, 1 << 16 | 0x20);
        let values: Vec<(u64, Vec<u8>)> = vec![
            (manager + 0x1c0, q(0x110_000)),
            (0x110_000, leaf(key, 0)),
            (manager, q(0x120_000)),
            (0x120_000, q(store)),
            (store + 0x1d00, q(owner)),
            (st + 0x320, q(store)),
            (store + 0x1b68, q(0x300_000)),
            (store + 0x1a95, vec![0b100]),
            (store + 0x12c0, d(0)),
            (st, q(0x130_000)),
            (0x130_000, leaf(key, region_key)),
            (st + 0x1c8, d(8)),
            (st + 0x1cc, d(0xff)),
            (st + 0x1d0, d(8)),
            (st + 0x1d8, d(0)),
            (st + 0xc0, q(0x140_000)),
            (0x140_000, q(0x150_000)),
            (0x150_010, d(record_key)),
            (0x150_014, d(data.len() as u32)),
            (st + 0x32c, d(16)),
            (st + 0x328, d(0xffff)),
            (0x300_008, q(0x0123_0000_0000 | 5)),
            // The region: 1 GiB page 0x8c of PML4 entry 2, at frame 0.
            (0x200, data),
            // PML4 at 0x400_000. Its entry 0 maps the store's structures
            // by a 1 GiB page at frame 0; 1 GiB up, PD entry 0 is in the
            // store.
            (0x400_000, q(0x401_000 | 0x7)),
            (0x400_010, q(0x402_000 | 0x7)),
            (0x401_000, q(0x87)),
            (0x401_008, q(0x403_000 | 0x7)),
            (0x402_000 + 0x8c * 8, q(0x87)),
            (0x403_000, q(stored)),
        ];
        let mut data = vec![0u8; 0x404_000];
        for (at, bytes) in &values {
            data[*at as usize..*at as usize + bytes.len()].copy_from_slice(bytes);
        }
        let layout = StoreLayout {
            owner_process: 0x1d00,
            region_array: 0x1b68,
            virtual_flag: (0x1a95, 2),
            back_pointer: 0x320,
            region_shift: 0x32c,
            region_offset_mask: 0x328,
            chunk_array: 0xc0,
            chunk_fields: [0x1c8, 0x1cc, 0x1d0, 0x1d8],
            key_tree: 0x1c0,
            pages_tree: 0,
            redirect_next: 4,
            compression: Compression::Lz4UnlessCount(0x12c0),
        };
        StoredPhysMem {
            memory: FakePhysMem {
                data,
                invalid_pte_mask: 0,
            },
            store: Arc::new(CompressedPages {
                layout,
                manager,
                owner,
                owner_root: 0x400_000,
                page_file: 2,
            }),
            page_file_low,
        }
    }

    /// Windows compresses a trimmed process's page tables into the store
    /// too. A walk goes on through a table read from there, to the pages
    /// its entries leave in the store: for a read, and for the walk of
    /// non-present PTEs.
    #[test]
    fn a_page_under_a_table_in_the_store_reads_through_the_store() {
        let stored = 0x0000_0042_0000_2080u64;
        let mem = stored_table(stored, PAGE_FILE_LOW);
        let space = AddressSpace::new_amd64(&mem, 0x400_000);
        let table = 0x4000_0000u64;
        let page = VirtAddr(table + 5 * PAGE_SIZE as u64);
        let mut buf = [0u8; 8];
        space.read_bytes(page + 40u64, &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), stored);
        space.read_bytes(page, &mut buf).unwrap();
        assert_eq!(buf, [0; 8]);
        let mut absent = Vec::new();
        space
            .for_each_absent_pte(VirtAddr(table), VirtAddr(table + 0x20_0000), |va, pte| {
                absent.push((va.0, pte.0));
            })
            .unwrap();
        assert_eq!(absent, [(page.0, stored)]);

        // Without the store, the table is out of reach.
        let plain = AddressSpace::new_amd64(&mem.memory, 0x400_000);
        assert!(plain.read_bytes(page, &mut buf).is_err());
    }

    /// Kernels before the L1TF mitigation keep the page-file number in bits
    /// 1-4, where a later kernel has its swizzle bit and others: read at
    /// bit 12, the same PTE names page file 0, which is not the store.
    #[test]
    fn the_page_file_number_is_read_where_the_kernel_keeps_it() {
        let stored = 0x0000_0042_0000_0084u64;
        let page = VirtAddr(0x4000_0000 + 5 * PAGE_SIZE as u64);
        let mut buf = [0u8; 8];
        let mem = stored_table(stored, 1);
        AddressSpace::new_amd64(&mem, 0x400_000)
            .read_bytes(page + 40u64, &mut buf)
            .unwrap();
        assert_eq!(u64::from_le_bytes(buf), stored);
        let mem = stored_table(stored, PAGE_FILE_LOW);
        assert!(
            AddressSpace::new_amd64(&mem, 0x400_000)
                .read_bytes(page, &mut buf)
                .is_err()
        );
    }

    /// A page table the guest trimmed stays in its frame while it is in
    /// transition; the walk reads it there, for a read, for the walk of
    /// non-present PTEs, and for the steps `!vtop` shows.
    #[test]
    fn a_page_under_a_table_in_transition_reads_from_its_frame() {
        // PD[0] at 0x3000 names the table at 0x4000, in transition; its
        // entry 2 is a page in transition at 0x5000.
        let mut data = vec![0u8; 0x6000];
        let mut put = |at: usize, value: u64| {
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(0x1000, 0x2000 | 0x7);
        put(0x2000, 0x3000 | 0x7);
        put(0x3000, 0x4000 | 1 << 11 | 0x80);
        put(0x4000 + 2 * 8, 0x5000 | 1 << 11 | 0x80);
        put(0x5000 + 0x18, 0x1122_3344_5566_7788);
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        let page = VirtAddr(2 * PAGE_SIZE as u64);
        assert_eq!(
            space.read::<u64>(page + 0x18u64).unwrap(),
            0x1122_3344_5566_7788
        );
        let mut absent = Vec::new();
        space
            .for_each_absent_pte(VirtAddr(0), VirtAddr(0x20_0000), |va, pte| {
                absent.push((va.0, pte.0));
            })
            .unwrap();
        assert_eq!(absent, [(page.0, 0x5000 | 1 << 11 | 0x80)]);
        let (steps, translation) = space.walk_steps(page).unwrap();
        assert_eq!(
            steps.iter().map(|step| step.address).collect::<Vec<_>>(),
            [0x1000, 0x2000, 0x3000, 0x4010]
        );
        assert_eq!(translation.map(|t| t.address), Some(0x5000));
    }

    /// A page that is not in memory says where it is: from its PTE, or from
    /// the entry above it that names a table not in memory.
    #[test]
    fn a_page_not_in_memory_says_where_it_is() {
        let page = |pte: u64| {
            let (mem, va) = amd64_space(pte);
            AddressSpace::new_amd64(&mem, 0x1000).non_resident(va)
        };
        let leaf = |place| Some(NonResident { table: None, place });
        assert_eq!(page(0x5000 | 0x3), None);
        assert_eq!(page(0x5000 | 1 << 11 | 0x80), None, "in transition");
        assert_eq!(page(0), leaf(Place::Unmapped));
        assert_eq!(page(0x80), leaf(Place::DemandZero));
        assert_eq!(page(0xffff_ffff_0000_0480), leaf(Place::Prototype));
        assert_eq!(
            page(0x1234 << 32 | 0x80),
            leaf(Place::PageFile {
                file: 0,
                offset: 0x1234
            })
        );

        // PD[0] is in page file 3: the table under it is.
        let mut data = vec![0u8; 0x4000];
        let mut put = |at: usize, value: u64| {
            data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(0x1000, 0x2000 | 0x7);
        put(0x2000, 0x3000 | 0x7);
        put(0x3000, 0x77 << 32 | 3 << 12 | 0x80);
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        assert_eq!(
            AddressSpace::new_amd64(&mem, 0x1000).non_resident(VirtAddr(0x5000)),
            Some(NonResident {
                table: Some(PageTableLevel::Pde),
                place: Place::PageFile {
                    file: 3,
                    offset: 0x77
                },
            })
        );

        // In the store: the page reads from there; a key the store does not
        // hold says why not.
        let stored = 0x0000_0042_0000_2080u64;
        let page = VirtAddr(0x4000_0000 + 5 * PAGE_SIZE as u64);
        let mem = stored_table(stored, PAGE_FILE_LOW);
        assert_eq!(
            AddressSpace::new_amd64(&mem, 0x400_000).non_resident(page),
            leaf(Place::Store {
                offset: 0x42,
                problem: None
            })
        );
        let mem = stored_table(0x0000_0043_0000_2080, PAGE_FILE_LOW);
        let missing = AddressSpace::new_amd64(&mem, 0x400_000).non_resident(page);
        assert!(
            matches!(
                missing,
                Some(NonResident {
                    table: Some(PageTableLevel::Pde),
                    place: Place::Store {
                        offset: 0x43,
                        problem: Some(_)
                    },
                })
            ),
            "{missing:?}"
        );
    }
    #[test]
    fn present_page_walk_skips_absent_tables_and_clips_large_pages() {
        // Kernel half: PML4[0x1f0] -> PDPT at 0x2000. PDPT[0] -> PD at
        // 0x3000; PDPT[1] is absent. PD[0] -> PT at 0x4000 with PTE 2
        // present and PTE 3 in transition; PD[1] is a 2 MiB page at
        // 0x20_0000.
        let mut data = vec![0u8; 0x5000];
        let mut put = |table: usize, index: usize, value: u64| {
            data[table + index * 8..table + index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(0x1000, 0x1f0, 0x2000 | 0b11);
        put(0x2000, 0, 0x3000 | 0b11);
        put(0x3000, 0, 0x4000 | 0b11);
        put(0x3000, 1, 0x20_0000 | 0x80 | 0b11);
        put(0x4000, 2, 0x9000 | 0b11);
        put(0x4000, 3, 0xa000 | (1 << 11));
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        let base = 0xffff_f800_0000_0000u64;
        let mut visits = Vec::new();
        space
            .for_each_present_page(
                VirtAddr(base + 0x1000),
                VirtAddr(base + 0x4000_0000 + 0x1000),
                |va, physical, length| {
                    visits.push((va.0 - base, physical, length));
                    ControlFlow::Continue(())
                },
            )
            .unwrap();
        assert_eq!(
            visits,
            [(0x2000, 0x9000, 0x1000), (0x20_0000, 0x20_0000, 0x20_0000)]
        );

        // A range starting inside the large page is clipped to it, and a
        // break stops the walk.
        let mut visits = Vec::new();
        space
            .for_each_present_page(
                VirtAddr(base + 0x30_0000),
                VirtAddr(base + 0x31_0000),
                |va, physical, length| {
                    visits.push((va.0 - base, physical, length));
                    ControlFlow::Break(())
                },
            )
            .unwrap();
        assert_eq!(visits, [(0x30_0000, 0x30_0000, 0x1_0000)]);
    }

    /// A trimmed page keeps its frame on the standby list with the valid bit
    /// clear. Refusing to read it would report memory as gone that the target
    /// can still show; writing it would edit a frame the kernel may reclaim.
    #[test]
    fn transition_pte_reads_the_frame_it_still_owns() {
        // PFN 0x5, valid clear, transition (bit 11) set.
        let (mem, va) = amd64_space(0x5000 | (1 << 11));
        let space = AddressSpace::new_amd64(&mem, 0x1000);

        let mut buf = [0u8; 8];
        space.read_bytes(va, &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0x1122_3344_5566_7788);

        let error = space.write_bytes(va, &[0xcc]).unwrap_err();
        // The walk refuses it; a write that got as far as the frame would
        // come back as this backend's `BadPhysicalAddress` instead.
        assert!(
            matches!(error, Error::DebugInfo(_)),
            "a standby frame is not mapped here and must not be written"
        );
    }

    /// Windows' L1TF mitigation sets a high bit (`InvalidPteMask`) in a
    /// non-present PTE's frame, recording that with `SwizzleBit` (bit 4)
    /// clear. A trimmed kernel stack's transition PTE read as-is points past
    /// RAM; its frame is the one with the mask cleared.
    #[test]
    fn a_swizzled_transition_pte_reads_its_real_frame() {
        const MASK: u64 = 1 << 45;
        let read = |leaf: u64| {
            let (mut mem, va) = amd64_space(leaf);
            mem.invalid_pte_mask = MASK;
            let mut buf = [0u8; 8];
            AddressSpace::new_amd64(&mem, 0x1000)
                .read_bytes(va, &mut buf)
                .map(|()| u64::from_le_bytes(buf))
        };
        assert_eq!(
            read(0x5000 | MASK | (1 << 11)).unwrap(),
            0x1122_3344_5566_7788
        );
        // With SwizzleBit set the entry was stored as-is: the bit is its own.
        assert!(read(0x5000 | MASK | (1 << 11) | (1 << 4)).is_err());
    }

    /// The other invalid forms store a prototype-PTE pointer or a page-file
    /// offset where a transition PTE stores a frame. Reading those bits as a
    /// frame would hand back unrelated physical memory as if it were the
    /// caller's page.
    #[test]
    fn prototype_and_pagefile_ptes_are_not_read_as_frames() {
        for (name, leaf) in [
            ("prototype", 0x5000 | (1 << 11) | (1 << 10)),
            ("page file", 0x5000u64),
        ] {
            let (mem, va) = amd64_space(leaf);
            let space = AddressSpace::new_amd64(&mem, 0x1000);
            let mut buf = [0u8; 8];
            assert!(
                space.read_bytes(va, &mut buf).is_err(),
                "{name} PTE was followed as if its bits were a page frame"
            );
        }
    }

    /// A large-page entry's bit 12 is PAT, not address. Read as a frame bit,
    /// every PAT-typed large mapping resolves one page off.
    #[test]
    fn large_page_walk_ignores_pat_bit() {
        const PAT: u64 = 1 << 12;
        let (mem, _) = amd64_space(0);
        let mut data = mem.data;
        let va = VirtAddr(0x0020_0000 + 0x1008);
        let pde_at = 0x3000 + va.pd_index() * 8;
        data[pde_at..pde_at + 8]
            .copy_from_slice(&(0x0040_0000 | PAT | 0x80 | 0b111u64).to_le_bytes());
        data.resize(0x0060_0000, 0);
        data[0x0040_1008..0x0040_1010].copy_from_slice(&0xfeed_faceu64.to_le_bytes());
        data[0x0040_2008..0x0040_2010].copy_from_slice(&0xbad_f00du64.to_le_bytes());
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };

        let value: u64 = AddressSpace::new_amd64(&mem, 0x1000).read(va).unwrap();

        assert_eq!(value, 0xfeed_face);
    }

    #[test]
    fn identity_dtb_skips_page_table_walk() {
        let mut data = vec![0u8; 0x2000];
        data[0x1000..0x1008].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_amd64(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 8];
        space.read_bytes(VirtAddr(0x1000), &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn identity_dtb_cross_boundary_read() {
        let mut data = vec![0u8; 0x3000];
        for (i, byte) in data[0xFF0..0x1010].iter_mut().enumerate() {
            *byte = ((0xFF0 + i) & 0xFF) as u8;
        }
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_amd64(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 0x20];
        space.read_bytes(VirtAddr(0xFF0), &mut buf).unwrap();
        assert_eq!(buf[0], 0xF0);
        assert_eq!(buf[0x10], 0x00); // 0x1000 & 0xFF
        assert_eq!(buf[0x1F], 0x0F); // 0x100F & 0xFF
    }

    #[test]
    fn arm64_kernel_walk_uses_upper_half_of_combined_root_page() {
        let mut data = vec![0u8; 0x6000];
        let kernel_va = VirtAddr(0xffff_8000_0000_0000);
        let root_page = 0x1000u64;
        data[root_page as usize + kernel_va.pml4_index() * 8
            ..root_page as usize + kernel_va.pml4_index() * 8 + 8]
            .copy_from_slice(&(0x2000u64 | 0b11).to_le_bytes());
        data[0x2000..0x2008].copy_from_slice(&(0x3000u64 | 0b11).to_le_bytes());
        data[0x3000..0x3008].copy_from_slice(&(0x4000u64 | 0b11).to_le_bytes());
        data[0x4000..0x4008].copy_from_slice(&(0x5000u64 | 0b11).to_le_bytes());
        data[0x5000..0x5008].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        let mem = FakePhysMem {
            data,
            invalid_pte_mask: 0,
        };
        let space = AddressSpace::new_arm64(&mem, root_page, root_page);

        let value: u64 = space.read(kernel_va).unwrap();

        assert_eq!(value, 0xDEAD_BEEF_CAFE_BABE);
    }
    /// ARM64 Windows trims a page as AMD64 Windows does, into an
    /// `_MMPTE_TRANSITION` with the same bit layout; a swapped-out kernel
    /// stack is read through one.
    #[test]
    fn arm64_transition_pte_reads_the_frame_it_still_owns() {
        let read = |leaf: u64| {
            let mut data = vec![0u8; 0x7000];
            for (table, next) in [(0x1000usize, 0x2000u64), (0x2000, 0x3000), (0x3000, 0x4000)] {
                data[table..table + 8].copy_from_slice(&(next | 0b11).to_le_bytes());
            }
            data[0x4000..0x4008].copy_from_slice(&leaf.to_le_bytes());
            data[0x6000..0x6008].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
            let mem = FakePhysMem {
                data,
                invalid_pte_mask: 0,
            };
            AddressSpace::new_arm64(&mem, 0x1000, 0x1000)
                .read::<u64>(VirtAddr(0))
                .ok()
        };
        assert_eq!(read(0x6000 | (1 << 11)), Some(0x1122_3344_5566_7788));
        // A prototype or page-file entry holds no frame.
        assert_eq!(read(0x6000 | (1 << 11) | (1 << 10)), None);
        assert_eq!(read(0x6000), None);
    }

    /// AP[1] (bit 6) opens a page to EL0 and AP[2] (bit 7) makes it
    /// read-only; the execute-never bit that applies is UXN for a user
    /// address and PXN for a kernel one. A Windows user page's level-0 entry
    /// has APTable[0] set, which with hierarchical permissions on would
    /// forbid EL0 access, so table bits must not restrict (Windows sets
    /// `TCR_EL1.HPD`).
    #[test]
    fn arm64_permissions_come_from_the_mapping_descriptor() {
        let read = |leaf: u64, va: u64| {
            let mut data = vec![0u8; 0x7000];
            let va = VirtAddr(va);
            // A user page's real level-0 entry: APTable[0] (bit 61) and
            // NSTable set.
            for (table, index, next) in [
                (0x1000usize, va.pml4_index(), 0x2000u64 | 0xa0e0 << 48),
                (0x2000, va.pdpt_index(), 0x3000),
                (0x3000, va.pd_index(), 0x4000),
            ] {
                let at = table + index * 8;
                data[at..at + 8].copy_from_slice(&(next | 0b11).to_le_bytes());
            }
            let at = 0x4000 + va.pt_index() * 8;
            data[at..at + 8].copy_from_slice(&(leaf | 0x6000 | 0b11).to_le_bytes());
            let mem = FakePhysMem {
                data,
                invalid_pte_mask: 0,
            };
            AddressSpace::new_arm64(&mem, 0x1000, 0x1000)
                .virt_to_phys(va)
                .unwrap()
                .unwrap()
        };
        const USER: u64 = 1 << 6;
        const READ_ONLY: u64 = 1 << 7;
        const PXN: u64 = 1 << 53;
        const UXN: u64 = 1 << 54;

        // A thread's TEB: user, never executed.
        let teb = read(USER | UXN | PXN, 0x26f_4000);
        assert_eq!(teb.address, 0x6000);
        assert!(teb.user && teb.nx);
        // User code: user, executable at EL0.
        let code = read(USER | READ_ONLY | PXN, 0x7762_0000);
        assert!(code.user && !code.nx);
        // Kernel code: EL1 only, executable at EL1.
        let kernel = read(READ_ONLY | UXN, 0xffff_f803_3f0e_b000);
        assert!(!kernel.user && !kernel.nx && kernel.uxn);
    }

    struct CachingPhysMem {
        inner: FakePhysMem,
        reads: std::cell::Cell<usize>,
        cache: TranslationCache,
    }

    impl MemoryOps<PhysAddr> for CachingPhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_bytes(addr, buf)
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            self.inner.write_bytes(addr, buf)
        }

        fn translation_cache(&self) -> Option<&TranslationCache> {
            Some(&self.cache)
        }
    }

    #[test]
    fn translation_cache_skips_repeat_walks_across_instances() {
        let mut data = vec![0u8; 0x6000];
        let va = VirtAddr(0x7fff_1234_5000);
        let root = 0x1000usize;
        let mut entry = |table: usize, index: usize, next: u64| {
            data[table + index * 8..table + index * 8 + 8]
                .copy_from_slice(&(next | 0b111).to_le_bytes());
        };
        entry(root, va.pml4_index(), 0x2000);
        entry(0x2000, va.pdpt_index(), 0x3000);
        entry(0x3000, va.pd_index(), 0x4000);
        entry(0x4000, va.pt_index(), 0x5000);
        data[0x5000..0x5008].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        data[0x5010..0x5018].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
        let mem = CachingPhysMem {
            inner: FakePhysMem {
                data,
                invalid_pte_mask: 0,
            },
            reads: std::cell::Cell::new(0),
            cache: TranslationCache::default(),
        };

        let first: u64 = AddressSpace::new_amd64(&mem, root as u64).read(va).unwrap();
        assert_eq!(first, 0x1111_2222_3333_4444);
        assert_eq!(mem.reads.get(), 5);

        let second: u64 = AddressSpace::new_amd64(&mem, root as u64)
            .read(VirtAddr(va.0 + 0x10))
            .unwrap();
        assert_eq!(second, 0x5555_6666_7777_8888);
        assert_eq!(mem.reads.get(), 6);

        mem.cache.clear();
        let _: u64 = AddressSpace::new_amd64(&mem, root as u64).read(va).unwrap();
        assert_eq!(mem.reads.get(), 11);
    }

    /// [`FakePhysMem`] with the guest's mapped views.
    struct ViewedPhysMem {
        inner: FakePhysMem,
        views: Arc<SectionViews>,
    }

    impl MemoryOps<PhysAddr> for ViewedPhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.inner.read_bytes(addr, buf)
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            self.inner.write_bytes(addr, buf)
        }

        fn section_views(&self) -> Option<Arc<SectionViews>> {
            Some(Arc::clone(&self.views))
        }
    }

    /// [`amd64_space`] with its user page at vpn 0x10 and the next one in a
    /// view, `flags` its VAD flags: one process, one VAD, and the view's two
    /// prototype PTEs, valid for frame 0x5000 and transition for 0x6000, in a
    /// kernel page at `KERNEL`.
    const KERNEL: u64 = 0xffff_8000_0000_0000;
    fn viewed_space(leaf: u64, flags: u32) -> (ViewedPhysMem, VirtAddr) {
        let (mut mem, va) = amd64_space(leaf);
        mem.data.resize(0xC000, 0);
        let mut put = |at: u64, value: u64| {
            let at = at as usize;
            mem.data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        let kernel = VirtAddr(KERNEL);
        put(0x1000 + 8 * kernel.pml4_index() as u64, 0x9000 | 0b11);
        put(0x9000, 0xA000 | 0b11);
        put(0xA000, 0xB000 | 0b11);
        put(0xB000, 0x8000 | 0b11);
        let page = |offset: u64| 0x8000 + offset;
        put(page(0x000), KERNEL + 0x110); // PsActiveProcessHead
        put(page(0x110), KERNEL); // the process's ActiveProcessLinks
        put(page(0x128), 0x1000); // its DirectoryTableBase
        put(page(0x140), KERNEL + 0x200); // its VadRoot
        put(page(0x218), 0x11 << 32 | 0x10); // VAD StartingVpn, EndingVpn
        put(page(0x230), u64::from(flags));
        put(page(0x250), KERNEL + 0x300); // FirstPrototypePte
        put(page(0x258), KERNEL + 0x308); // LastContiguousPte
        put(page(0x300), 0x5000 | 1);
        put(page(0x308), 0x6000 | 1 << 11);
        put(0x6000, 0x9999_aaaa_bbbb_cccc);
        let views = SectionViews::new(SectionLayout {
            process_list_head: kernel,
            active_process_links: 0x10,
            directory_table_base: 0x28,
            root_mask: PFN_MASK,
            vad_root: 0x40,
            left: 0,
            right: 8,
            vad_node: 0,
            starting_vpn: 0x18,
            ending_vpn: 0x1c,
            starting_vpn_high: None,
            ending_vpn_high: None,
            vad_flags: 0x30,
            private_memory_bit: 21,
            first_prototype_pte: 0x50,
            last_contiguous_pte: 0x58,
        });
        let mem = ViewedPhysMem {
            inner: mem,
            views: Arc::new(views),
        };
        (mem, va)
    }

    /// A process's PTE for a page of an image or file view stays empty until
    /// the process touches the page, but the page is often in memory for the
    /// others mapping it, recorded in the section's prototype PTEs. The page
    /// reads from there, whether the PTE is empty, its table absent, or it
    /// points at the prototype PTE; it is never written, since this process
    /// does not map it.
    #[test]
    fn an_untouched_view_page_reads_the_frame_its_section_holds() {
        let read =
            |space: &AddressSpace<'_, ViewedPhysMem>, va: VirtAddr| space.read::<u64>(va).ok();

        let (mem, va) = viewed_space(0, 0);
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        assert_eq!(read(&space, va), Some(0x1122_3344_5566_7788));
        assert_eq!(read(&space, va + 0x1000u64), Some(0x9999_aaaa_bbbb_cccc));
        assert!(matches!(
            space.write_bytes(va, &[0xcc]),
            Err(Error::DebugInfo(_))
        ));

        let pointer = (KERNEL + 0x308) << 16 | 1 << 10;
        let (mem, va) = viewed_space(pointer, 0);
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        assert_eq!(read(&space, va), Some(0x9999_aaaa_bbbb_cccc));

        let (mut mem, va) = viewed_space(0, 0);
        let pde = 0x3000 + 8 * va.pd_index();
        mem.inner.data[pde..pde + 8].fill(0);
        let space = AddressSpace::new_amd64(&mem, 0x1000);
        assert_eq!(read(&space, va), Some(0x1122_3344_5566_7788));
        // No view maps the pages below it.
        assert_eq!(read(&space, VirtAddr(va.0 - 0x10000)), None);
    }

    /// Private memory has no prototype PTEs; a VAD's `FirstPrototypePte`
    /// there is not one, and a page-file PTE is the process's own copy.
    #[test]
    fn private_and_paged_out_pages_are_not_read_from_a_section() {
        let (mem, va) = viewed_space(0, 1 << 21);
        assert!(
            AddressSpace::new_amd64(&mem, 0x1000)
                .read::<u64>(va)
                .is_err()
        );

        let (mem, va) = viewed_space(0x5000, 0);
        assert!(
            AddressSpace::new_amd64(&mem, 0x1000)
                .read::<u64>(va)
                .is_err()
        );
    }

    #[test]
    fn pattern_offsets_include_overlapping_matches() {
        let offsets = |haystack: &[u8], pattern: &[u8]| {
            pattern_offsets(haystack, pattern).collect::<Vec<_>>()
        };
        assert_eq!(offsets(b"aaaa", b"aa"), [0, 1, 2]);
        assert_eq!(offsets(b"abcab", b"ab"), [0, 3]);
        assert_eq!(offsets(b"ab", b"ab"), [0]);
        assert_eq!(offsets(b"a", b"ab"), [] as [usize; 0]);
    }

    /// A fault on the first page is the scan's error; an unreadable later
    /// page keeps the prefix and says so, unless the reader calls it fatal;
    /// the prefix holds whole units only.
    #[test]
    fn terminated_scan_keeps_the_prefix_before_an_unreadable_page() {
        const READABLE: u64 = 0x1000;
        let end = READABLE + PAGE_SIZE as u64;
        let read = |fatal: bool| {
            move |at: VirtAddr, buf: &mut [u8]| {
                if at.0 >= READABLE && at.0 < end {
                    buf.fill(b'A');
                    if at.0 + buf.len() as u64 == end {
                        buf[buf.len() - 1] = 0;
                    }
                    return Ok(());
                }
                let error = Error::BadVirtualAddress(at);
                Err(if fatal {
                    ScanFault::Fatal(error)
                } else {
                    ScanFault::Unreadable(error)
                })
            }
        };

        assert!(read_terminated(VirtAddr(end), 8, 1, read(false)).is_err());

        let tail = VirtAddr(end - 2);
        let prefix = read_terminated(tail, 8, 1, read(false)).unwrap();
        assert_eq!(prefix.bytes, b"A");
        assert!(!prefix.unreadable);

        let wide = read_terminated(VirtAddr(end - 3), 8, 2, read(false)).unwrap();
        assert_eq!(
            wide,
            TerminatedRead {
                bytes: b"AA".to_vec(),
                unreadable: true
            }
        );
        assert!(read_terminated(VirtAddr(end - 3), 8, 2, read(true)).is_err());
    }
}
