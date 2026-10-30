//! A record of the breakpoint instructions in guest memory that nothing else
//! would take out if this session died: sites this debugger patched itself
//! (user space), and sites planted through a backend whose target does not
//! reclaim them (a GDB stub; see
//! [`DebugBackend::reclaims_abandoned_breakpoints`]). Kept on disk, one file
//! per target endpoint, so a session that dies without restoring them, killed
//! or crashed, is repaired by the next attach to the same boot, through that
//! endpoint or another, instead of leaving a trap in code the guest runs.
//!
//! [`DebugBackend::reclaims_abandoned_breakpoints`]: crate::backend::dbg_backend::DebugBackend::reclaims_abandoned_breakpoints

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::backend::kd::trace_enabled;
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::{Dtb, PhysAddr, VirtAddr};

/// Original bytes kept per site, starting at the patched address: the
/// displaced instruction bytes, then untouched bytes that tell the same code
/// apart from a frame the guest has since reused.
const WINDOW: usize = 8;

/// A patched site: the original bytes from the site's physical address to
/// the end of the window or the page, whichever comes first, and the page
/// its frame held when it was planted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    original: Vec<u8>,
    /// `_MMPFN.PteAddress` of the site's frame when it was planted: the PTE
    /// that maps the page. For a page of a shared image that is the image
    /// section's prototype PTE, the same in every process mapping the image,
    /// so it outlives the process the site was planted in; a frame the guest
    /// has since given to another page names that page's PTE instead. `None`
    /// when not known: a journal written before it was recorded, or a PFN
    /// database that could not be read.
    pte: Option<u64>,
}

/// Guest-physical memory a journaled site is restored in, and which page
/// each frame holds.
pub trait SiteMemory: MemoryOps<PhysAddr> {
    /// `_MMPFN.PteAddress` of the frame holding `address`, or `None` when
    /// the PFN database cannot be read.
    fn pte_address(&self, address: PhysAddr) -> Option<u64>;
}

/// The sites one session has patched into one target, mirrored to a file
/// named for the target. The instance lock gives each target one session at
/// a time, so the file has one writer.
#[derive(Debug)]
pub struct SiteJournal {
    path: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Kernel base of the boot the sites were written in. A reboot discards
    /// guest memory, and every site with it.
    kernel_base: u64,
    sites: BTreeMap<u64, Site>,
    /// The frame of each site this session planted, by the address space
    /// and virtual address it was planted at: what finds the site again once
    /// that address no longer translates, as when its process has exited.
    planted: BTreeMap<(Dtb, u64), PhysAddr>,
    /// What the file holds, as last written: a write that would not change
    /// it is skipped, since each one is synced to disk.
    written: Option<String>,
}

/// What an attach found of a previous session's sites.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Repair {
    /// Sites whose original bytes were written back.
    pub restored: usize,
    /// Sites that could not be written back; they stay journaled for the next
    /// attach.
    pub failed: usize,
}

impl SiteJournal {
    /// The journal for `key` (a target's instance-lock key) under `dir`,
    /// holding what a previous session in this boot left behind. Sites from
    /// another boot are dropped: that memory is gone.
    pub fn open(dir: &Path, key: &str, kernel_base: u64) -> Self {
        let path = dir.join(key);
        // Only a missing file means there is nothing to repair. Rewriting a
        // journal that exists but could not be read would delete the only
        // record of sites still patched in the guest, so it counts as already
        // holding the empty journal: it is left alone until this session
        // plants a site of its own.
        let (sites, written) = match fs::read_to_string(&path) {
            Ok(text) => (parse(&text, kernel_base), None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (BTreeMap::new(), None),
            Err(_) => (BTreeMap::new(), Some(String::new())),
        };
        let journal = Self {
            path,
            state: Mutex::new(State {
                kernel_base,
                sites,
                planted: BTreeMap::new(),
                written,
            }),
        };
        journal.persist(&mut journal.state());
        journal
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a site planted at `address` in `dtb`'s address space before
    /// its breakpoint instruction is written: the frame it translates to,
    /// the original bytes from there to the end of the window or page, and
    /// the frame's `_MMPFN.PteAddress` when the PFN database could be read.
    pub fn record(
        &self,
        dtb: Dtb,
        address: VirtAddr,
        frame: PhysAddr,
        original: &[u8],
        pte: Option<u64>,
    ) {
        let mut state = self.state();
        state.planted.insert((dtb, address.0), frame);
        state.sites.insert(
            frame,
            Site {
                original: original.to_vec(),
                pte,
            },
        );
        self.persist(&mut state);
    }

    /// Forget the site planted at `address` in `dtb`'s address space once its
    /// original bytes are back in guest memory. The file keeps it until the
    /// next write that changes it, until no site is left, or until the
    /// session ends: an entry for a site no longer patched only matters if
    /// this session is killed and another debugger plants the same bytes
    /// there before the next attach, while a site lifted to step past it and
    /// planted again (every pass over a hot breakpoint) then costs no write
    /// to disk.
    pub fn forget(&self, dtb: Dtb, address: VirtAddr) {
        let mut state = self.state();
        let Some(frame) = state.planted.remove(&(dtb, address.0)) else {
            return;
        };
        if state.sites.remove(&frame).is_some() && state.sites.is_empty() {
            self.persist(&mut state);
        }
    }

    /// Take out the site planted at `address` in `dtb`'s address space
    /// through the frame it was planted in, when that address no longer
    /// translates there (its process has exited, taking its page tables).
    /// The frame is written only when it still holds the breakpoint and the
    /// page it was planted in, as on the next attach's [`Self::repair`]; a
    /// site that does not is dropped untouched, and one whose page cannot be
    /// told stays journaled for the next attach. A frame that cannot be read
    /// or written leaves the site as it was, for the caller to try again.
    /// The frame and what it found, or `None` when this session did not
    /// plant the site.
    pub fn lift(
        &self,
        dtb: Dtb,
        address: VirtAddr,
        memory: &impl SiteMemory,
        opcode: &[u8],
    ) -> Option<(PhysAddr, Restore)> {
        let mut state = self.state();
        let frame = *state.planted.get(&(dtb, address.0))?;
        let site = state.sites.get(&frame)?;
        let restore = restore(memory, opcode, frame, site);
        match restore {
            Restore::Restored | Restore::NotPatched | Restore::Reused { .. } => {
                state.planted.remove(&(dtb, address.0));
                state.sites.remove(&frame);
                self.persist(&mut state);
            }
            Restore::Unconfirmed => {
                state.planted.remove(&(dtb, address.0));
            }
            Restore::Unreadable | Restore::Failed => {}
        }
        Some((frame, restore))
    }

    /// Start over for a new boot: every recorded site went with the old
    /// memory. A reload that found the same kernel keeps them.
    pub fn rebase(&self, kernel_base: u64) {
        let mut state = self.state();
        if state.kernel_base != kernel_base {
            state.kernel_base = kernel_base;
            state.sites.clear();
            state.planted.clear();
            self.persist(&mut state);
        }
    }

    /// Put back every site a previous session left patched. A site is only
    /// written when its frame still holds `opcode` followed by exactly the
    /// bytes recorded after it, and still holds the page it was planted in;
    /// anything else means the guest restored it or reused the frame, and
    /// the entry is dropped untouched. One whose page cannot be told, or
    /// whose frame cannot be read, is kept for the next attach.
    pub fn repair(&self, memory: &impl SiteMemory, opcode: &[u8]) -> Repair {
        let mut state = self.state();
        let mut repair = Repair::default();
        let sites: Vec<(u64, Site)> = state
            .sites
            .iter()
            .map(|(address, site)| (*address, site.clone()))
            .collect();
        for (address, site) in sites {
            match restore(memory, opcode, address, &site) {
                Restore::Restored => {
                    state.sites.remove(&address);
                    repair.restored += 1;
                }
                Restore::NotPatched => {
                    state.sites.remove(&address);
                }
                Restore::Reused { now } => {
                    if trace_enabled() {
                        eprintln!(
                            "breakpoint: journaled site at frame {address:#x} dropped: the frame now \
                             holds the page of PTE {now:#x}, not the one it was planted in"
                        );
                    }
                    state.sites.remove(&address);
                }
                Restore::Unconfirmed | Restore::Unreadable | Restore::Failed => repair.failed += 1,
            }
        }
        self.persist(&mut state);
        repair
    }

    /// Put back the sites a dead session left in this boot through another
    /// endpoint, `key` (a KD attach after a GDB session died). The caller
    /// holds that endpoint's instance lock, so no session owns the file. Only
    /// sites still patched here are touched: the file may also hold another
    /// boot's, or another VM's, which stay as they are.
    pub fn repair_orphaned(
        dir: &Path,
        key: &str,
        kernel_base: u64,
        memory: &impl SiteMemory,
        opcode: &[u8],
    ) -> Repair {
        let path = dir.join(key);
        let Ok(text) = fs::read_to_string(&path) else {
            return Repair::default();
        };
        let mut repair = Repair::default();
        let mut kept = String::new();
        for line in text.lines() {
            let Some((base, address, site)) = parse_line(line) else {
                continue;
            };
            if base == kernel_base && restore(memory, opcode, address, &site) == Restore::Restored {
                repair.restored += 1;
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        if repair.restored != 0 {
            write_atomically(&path, &kept);
        }
        repair
    }

    /// Mirror the state to disk. An empty journal removes the file.
    /// Persistence is best effort: a journal that cannot be written costs the
    /// repair after a crash, not the breakpoint.
    fn persist(&self, state: &mut State) {
        let mut text = String::new();
        for (address, site) in &state.sites {
            let bytes: String = site.original.iter().map(|b| format!("{b:02x}")).collect();
            text.push_str(&format!("{:x} {address:x} {bytes}", state.kernel_base));
            if let Some(pte) = site.pte {
                text.push_str(&format!(" {pte:x}"));
            }
            text.push('\n');
        }
        if state.written.as_ref() == Some(&text) {
            return;
        }
        if write_atomically(&self.path, &text) {
            state.written = Some(text);
        }
    }
}

/// A session that ends writes the sites it forgot but kept in the file, so
/// the next attach finds only what is still patched.
impl Drop for SiteJournal {
    fn drop(&mut self) {
        let mut state = self.state();
        self.persist(&mut state);
    }
}

/// What restoring one journaled site found.
#[derive(Debug, PartialEq, Eq)]
pub enum Restore {
    /// Its original instruction was written back.
    Restored,
    /// Its frame no longer holds the breakpoint and the recorded bytes after
    /// it: the guest restored it or reused the frame.
    NotPatched,
    /// Its frame still reads as the site, but holds another page now, the
    /// one PTE `now` maps: the guest reused the frame, and what reads as the
    /// site is that page's own data.
    Reused { now: u64 },
    /// Its frame still reads as the site, but the PFN database could not be
    /// read to tell whether it still holds the page the site was planted in.
    Unconfirmed,
    /// Its frame could not be read, so whether it still holds the breakpoint
    /// is not known: a read that times out says nothing about the site.
    Unreadable,
    /// Still patched, but the write failed.
    Failed,
}

/// Write `site`'s displaced instruction back at `address` if the frame still
/// holds `opcode` followed by exactly the bytes recorded after it, and the
/// page recorded for it.
///
/// A site with no page recorded, from a journal an older version wrote, is
/// judged by its bytes alone, as that version would have: dropping it
/// instead would leave a breakpoint instruction in code every process
/// mapping the page runs, which kills the first one to reach it once no
/// debugger is attached, while a frame reused for other data that holds the
/// breakpoint followed by the very bytes the site displaced, at the same
/// offset, is not a case worth trading that for.
fn restore(memory: &impl SiteMemory, opcode: &[u8], address: u64, site: &Site) -> Restore {
    let mut current = vec![0u8; site.original.len()];
    if memory.read_bytes(address, &mut current).is_err() {
        return Restore::Unreadable;
    }
    let still_patched = site.original.len() >= opcode.len()
        && current[..opcode.len()] == *opcode
        && current[opcode.len()..] == site.original[opcode.len()..];
    if !still_patched {
        return Restore::NotPatched;
    }
    if let Some(recorded) = site.pte {
        match memory.pte_address(address) {
            Some(now) if now == recorded => {}
            Some(now) => return Restore::Reused { now },
            None => return Restore::Unconfirmed,
        }
    }
    match memory.write_bytes(address, &site.original[..opcode.len()]) {
        Ok(()) => Restore::Restored,
        Err(_) => Restore::Failed,
    }
}

/// Replace `path` with `text` in one rename, so a crash mid-write leaves the
/// previous record rather than a torn one; empty `text` removes the file.
/// Whether the file now holds `text`.
fn write_atomically(path: &Path, text: &str) -> bool {
    if text.is_empty() {
        return match fs::remove_file(path) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
    }
    let staging = path.with_extension("tmp");
    fs::File::create(&staging)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| fs::rename(&staging, path))
        .is_ok()
}

/// The window of original bytes to record for a site at `address` whose
/// bytes from there are `bytes`: at most [`WINDOW`], never past the page.
pub fn site_window(address: PhysAddr, bytes: &[u8]) -> &[u8] {
    let to_page_end = PAGE_SIZE - (address as usize & (PAGE_SIZE - 1));
    &bytes[..bytes.len().min(WINDOW).min(to_page_end)]
}

/// Parse `<kernel base> <physical address> <original bytes> [<PTE address>]`
/// lines, keeping the sites of the boot at `kernel_base`.
fn parse(text: &str, kernel_base: u64) -> BTreeMap<u64, Site> {
    text.lines()
        .filter_map(parse_line)
        .filter(|(base, _, _)| *base == kernel_base)
        .map(|(_, address, site)| (address, site))
        .collect()
}

/// One `<kernel base> <physical address> <original bytes> [<PTE address>]`
/// line. The PTE address came later: a line an older version wrote has none,
/// and that version reads only the first three fields of a newer one.
fn parse_line(line: &str) -> Option<(u64, u64, Site)> {
    let mut fields = line.split_whitespace();
    let base = u64::from_str_radix(fields.next()?, 16).ok()?;
    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
    let hex = fields.next()?;
    let original = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let pte = match fields.next() {
        Some(field) => Some(u64::from_str_radix(field, 16).ok()?),
        None => None,
    };
    (!original.is_empty()).then_some((base, address, Site { original, pte }))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;
    use crate::base::error::{Error, Result};

    const INT3: &[u8] = &[0xcc];
    const BASE: u64 = 0xfffff805_afbc0000;
    /// The address space sites are planted in.
    const DTB: Dtb = 0x1ad000;
    /// The page every frame holds unless a test says otherwise: a prototype
    /// PTE of a shared image.
    const PTE: u64 = 0xffffb30a_6c41f2b8;
    /// A page the guest reused a frame for.
    const OTHER_PTE: u64 = 0xfffff3f9_bf8e3c40;

    /// Physical memory as a sparse byte map; `read_only` fails every write.
    /// Each frame holds the page [`PTE`] maps unless `ptes` names another,
    /// and none can be told when `no_pfn_database` is set.
    #[derive(Default)]
    struct Frames {
        bytes: RefCell<HashMap<u64, u8>>,
        ptes: HashMap<u64, u64>,
        read_only: bool,
        no_pfn_database: bool,
    }

    impl Frames {
        fn with(address: u64, bytes: &[u8]) -> Self {
            let frames = Self::default();
            frames.put(address, bytes);
            frames
        }

        fn put(&self, address: u64, bytes: &[u8]) {
            let mut map = self.bytes.borrow_mut();
            for (offset, byte) in bytes.iter().enumerate() {
                map.insert(address + offset as u64, *byte);
            }
        }

        fn get(&self, address: u64, len: usize) -> Vec<u8> {
            let map = self.bytes.borrow();
            (0..len as u64)
                .map(|offset| map[&(address + offset)])
                .collect()
        }
    }

    impl MemoryOps<PhysAddr> for Frames {
        fn read_bytes(&self, address: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let map = self.bytes.borrow();
            for (offset, byte) in buf.iter_mut().enumerate() {
                *byte = *map
                    .get(&(address + offset as u64))
                    .ok_or(Error::BadPhysicalAddress(address))?;
            }
            Ok(())
        }

        fn write_bytes(&self, address: PhysAddr, buf: &[u8]) -> Result<()> {
            if self.read_only {
                return Err(Error::BadPhysicalAddress(address));
            }
            self.put(address, buf);
            Ok(())
        }
    }

    impl SiteMemory for Frames {
        fn pte_address(&self, address: PhysAddr) -> Option<u64> {
            let page = address & !(PAGE_SIZE as u64 - 1);
            (!self.no_pfn_database).then(|| self.ptes.get(&page).copied().unwrap_or(PTE))
        }
    }

    /// A private directory per test, removed when the test ends.
    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ntoseye-site-journal-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `mov r10, rcx; mov eax, 0Fh`: the start of ntdll!NtClose.
    const NTCLOSE: [u8; 8] = [0x4c, 0x8b, 0xd1, 0xb8, 0x0f, 0x00, 0x00, 0x00];

    fn patched() -> [u8; 8] {
        let mut bytes = NTCLOSE;
        bytes[0] = 0xcc;
        bytes
    }

    /// Record a site in the frame at `frame`, planted at the virtual address
    /// of the same value in [`DTB`]'s address space, in a page [`PTE`] maps.
    fn plant(journal: &SiteJournal, frame: u64) {
        journal.record(DTB, VirtAddr(frame), frame, &NTCLOSE, Some(PTE));
    }

    /// The case a killed session leaves: a site recorded, never restored.
    fn stranded(dir: &Dir, address: u64) {
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        plant(&journal, address);
    }

    #[test]
    fn a_site_left_patched_by_a_dead_session_is_restored_on_the_next_attach() {
        let dir = Dir::new("restore");
        stranded(&dir, 0x26a06bf90);
        let frames = Frames::with(0x26a06bf90, &patched());

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(
            journal.repair(&frames, INT3),
            Repair {
                restored: 1,
                failed: 0
            }
        );
        assert_eq!(frames.get(0x26a06bf90, 8), NTCLOSE);
        // Repaired sites are gone from the record.
        assert!(!dir.0.join("target").exists());
    }

    #[test]
    fn a_frame_that_no_longer_holds_the_site_is_left_alone() {
        let dir = Dir::new("reused");
        stranded(&dir, 0x1000);
        stranded(&dir, 0x2000);
        // 0x1000: the guest already put the byte back. 0x2000: the frame now
        // holds other data that happens to start with 0xcc.
        let frames = Frames::with(0x1000, &NTCLOSE);
        frames.put(0x2000, &[0xcc, 1, 2, 3, 4, 5, 6, 7]);

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(journal.repair(&frames, INT3), Repair::default());
        assert_eq!(frames.get(0x1000, 8), NTCLOSE);
        assert_eq!(frames.get(0x2000, 8), [0xcc, 1, 2, 3, 4, 5, 6, 7]);
        assert!(!dir.0.join("target").exists());
    }

    /// A frame the guest gave to another page can hold the breakpoint and
    /// the bytes after it as that page's own data; it is not written.
    #[test]
    fn a_frame_that_now_holds_another_page_is_left_alone() {
        let dir = Dir::new("other-page");
        stranded(&dir, 0x26a06bf90);
        let frames = Frames {
            ptes: HashMap::from([(0x26a06b000, OTHER_PTE)]),
            ..Frames::with(0x26a06bf90, &patched())
        };

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(journal.repair(&frames, INT3), Repair::default());
        assert_eq!(frames.get(0x26a06bf90, 8), patched());
        assert!(!dir.0.join("target").exists());
    }

    /// Without the PFN database a site still patched cannot be told from a
    /// reused frame, so it is neither written nor dropped.
    #[test]
    fn a_site_whose_page_cannot_be_told_stays_journaled() {
        let dir = Dir::new("no-pfn");
        stranded(&dir, 0x26a06bf90);
        let frames = Frames {
            no_pfn_database: true,
            ..Frames::with(0x26a06bf90, &patched())
        };

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(
            journal.repair(&frames, INT3),
            Repair {
                restored: 0,
                failed: 1
            }
        );
        assert_eq!(frames.get(0x26a06bf90, 8), patched());
        drop(journal);
        let retry = SiteJournal::open(&dir.0, "target", BASE);
        let frames = Frames::with(0x26a06bf90, &patched());
        assert_eq!(retry.repair(&frames, INT3).restored, 1);
    }

    /// A journal an older version wrote records no page: its sites are
    /// judged by their bytes alone, as that version judged them, whatever
    /// page the frame holds (see `restore`). A site journaled now records
    /// its page as a fourth field.
    #[test]
    fn a_site_journaled_without_its_page_is_judged_by_its_bytes() {
        let dir = Dir::new("old-format");
        let bytes: String = NTCLOSE.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(
            dir.0.join("target"),
            format!("{BASE:x} 26a06bf90 {bytes}\n"),
        )
        .unwrap();
        let frames = Frames {
            ptes: HashMap::from([(0x26a06b000, OTHER_PTE)]),
            ..Frames::with(0x26a06bf90, &patched())
        };

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(journal.repair(&frames, INT3).restored, 1);
        assert_eq!(frames.get(0x26a06bf90, 8), NTCLOSE);

        plant(&journal, 0x1000);
        assert_eq!(
            fs::read_to_string(dir.0.join("target")).unwrap(),
            format!("{BASE:x} 1000 {bytes} {PTE:x}\n")
        );
    }

    /// A site whose address no longer translates (its process exited) is
    /// taken out through the frame it was planted in: written back only
    /// while that frame holds the breakpoint and the same page, and dropped
    /// from the journal either way.
    #[test]
    fn a_site_is_lifted_through_its_frame_only_while_it_holds_the_same_page() {
        let dir = Dir::new("lift");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        for frame in [0x1000, 0x2000, 0x3000] {
            plant(&journal, frame);
        }
        // 0x1000 still holds the site's page; 0x2000 was reused for another
        // page that reads the same; 0x3000 no longer holds the breakpoint.
        let frames = Frames {
            ptes: HashMap::from([(0x2000, OTHER_PTE)]),
            ..Frames::with(0x1000, &patched())
        };
        frames.put(0x2000, &patched());
        frames.put(0x3000, &NTCLOSE);
        let lift = |frame| journal.lift(DTB, VirtAddr(frame), &frames, INT3);

        assert_eq!(lift(0x1000), Some((0x1000, Restore::Restored)));
        assert_eq!(frames.get(0x1000, 8), NTCLOSE);
        assert_eq!(
            lift(0x2000),
            Some((0x2000, Restore::Reused { now: OTHER_PTE }))
        );
        assert_eq!(frames.get(0x2000, 8), patched());
        assert_eq!(lift(0x3000), Some((0x3000, Restore::NotPatched)));
        assert_eq!(frames.get(0x3000, 8), NTCLOSE);
        assert!(!dir.0.join("target").exists());
        // Gone from the journal, and never planted at all, alike.
        assert_eq!(lift(0x1000), None);
        assert_eq!(
            journal.lift(DTB + 0x1000, VirtAddr(0x1000), &frames, INT3),
            None
        );
    }

    /// A lift that cannot tell the frame's page leaves the site journaled,
    /// for the next attach to restore.
    #[test]
    fn a_site_lifted_without_the_pfn_database_is_left_to_the_next_attach() {
        let dir = Dir::new("lift-no-pfn");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        plant(&journal, 0x1000);
        let frames = Frames {
            no_pfn_database: true,
            ..Frames::with(0x1000, &patched())
        };

        assert_eq!(
            journal.lift(DTB, VirtAddr(0x1000), &frames, INT3),
            Some((0x1000, Restore::Unconfirmed))
        );
        assert_eq!(frames.get(0x1000, 8), patched());
        drop(journal);
        let next = SiteJournal::open(&dir.0, "target", BASE);
        let frames = Frames::with(0x1000, &patched());
        assert_eq!(next.repair(&frames, INT3).restored, 1);
    }

    /// A read of the frame that fails, as one over a KD link that times
    /// out, says nothing about whether the breakpoint is still there: the
    /// site stays, and a later lift that can read the frame restores it.
    #[test]
    fn a_site_whose_frame_cannot_be_read_is_kept_for_the_next_lift() {
        let dir = Dir::new("lift-unreadable");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        plant(&journal, 0x1000);

        assert_eq!(
            journal.lift(DTB, VirtAddr(0x1000), &Frames::default(), INT3),
            Some((0x1000, Restore::Unreadable))
        );
        assert!(dir.0.join("target").exists());
        let frames = Frames::with(0x1000, &patched());
        assert_eq!(
            journal.lift(DTB, VirtAddr(0x1000), &frames, INT3),
            Some((0x1000, Restore::Restored))
        );
        assert_eq!(frames.get(0x1000, 8), NTCLOSE);

        // An attach that cannot read the frame keeps the site for the next.
        plant(&journal, 0x2000);
        drop(journal);
        let next = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(
            next.repair(&Frames::default(), INT3),
            Repair {
                restored: 0,
                failed: 1
            }
        );
        drop(next);
        let last = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(
            last.repair(&Frames::with(0x2000, &patched()), INT3)
                .restored,
            1
        );
    }

    #[test]
    fn sites_from_another_boot_or_target_are_not_touched() {
        let dir = Dir::new("boot");
        stranded(&dir, 0x26a06bf90);
        let frames = Frames::with(0x26a06bf90, &patched());

        let other_target = SiteJournal::open(&dir.0, "other", BASE);
        assert_eq!(other_target.repair(&frames, INT3), Repair::default());
        let rebooted = SiteJournal::open(&dir.0, "target", BASE + 0x200000);
        assert_eq!(rebooted.repair(&frames, INT3), Repair::default());
        assert_eq!(frames.get(0x26a06bf90, 8), patched());
    }

    /// A journal that exists but cannot be read still records sites patched
    /// in the guest; opening it must not delete it.
    #[test]
    fn an_unreadable_journal_is_not_deleted() {
        let dir = Dir::new("unreadable");
        let path = dir.0.join("target");
        fs::write(&path, [0xff, 0xfe]).unwrap();

        drop(SiteJournal::open(&dir.0, "target", BASE));
        assert_eq!(fs::read(&path).unwrap(), [0xff, 0xfe]);
    }

    #[test]
    fn a_site_that_cannot_be_written_back_stays_journaled() {
        let dir = Dir::new("failed");
        stranded(&dir, 0x26a06bf90);
        let frames = Frames {
            read_only: true,
            ..Frames::with(0x26a06bf90, &patched())
        };

        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(
            journal.repair(&frames, INT3),
            Repair {
                restored: 0,
                failed: 1
            }
        );
        drop(journal);
        let retry = SiteJournal::open(&dir.0, "target", BASE);
        let frames = Frames::with(0x26a06bf90, &patched());
        assert_eq!(retry.repair(&frames, INT3).restored, 1);
    }

    /// Every pass over a hot breakpoint lifts its site and plants it again;
    /// that must not cost a synced write each time, while a new site must.
    #[test]
    fn a_site_lifted_and_planted_again_writes_nothing() {
        let dir = Dir::new("cycle");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        plant(&journal, 0x1000);
        plant(&journal, 0x2000);
        let path = dir.0.join("target");
        fs::remove_file(&path).unwrap();
        for _ in 0..3 {
            journal.forget(DTB, VirtAddr(0x1000));
            plant(&journal, 0x1000);
        }
        assert!(!path.exists(), "a lift and re-plant rewrote the journal");
        plant(&journal, 0x3000);
        assert!(path.exists(), "a new site was not written");
    }

    #[test]
    fn a_site_restored_cleanly_is_forgotten() {
        let dir = Dir::new("forget");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        plant(&journal, 0x1000);
        plant(&journal, 0x2000);
        journal.forget(DTB, VirtAddr(0x1000));
        drop(journal);

        let frames = Frames::with(0x1000, &patched());
        frames.put(0x2000, &patched());
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(journal.repair(&frames, INT3).restored, 1);
        assert_eq!(frames.get(0x1000, 8), patched());
        assert_eq!(frames.get(0x2000, 8), NTCLOSE);
    }

    /// Another endpoint's journal, left by a dead session (a GDB session, now
    /// a KD attach to the same VM): only sites of this boot that are still
    /// patched are written back; everything else in the file stays.
    #[test]
    fn an_orphaned_journal_is_repaired_only_where_this_boot_still_holds_its_sites() {
        let dir = Dir::new("orphaned");
        let bytes: String = NTCLOSE.iter().map(|b| format!("{b:02x}")).collect();
        let other_boot = BASE + 0x200000;
        fs::write(
            dir.0.join("other"),
            format!("{BASE:x} 1000 {bytes}\n{BASE:x} 2000 {bytes}\n{other_boot:x} 3000 {bytes}\n"),
        )
        .unwrap();
        // 0x1000 is still patched; 0x2000 was put back since; 0x3000 holds a
        // breakpoint, but its entry is from another boot (or VM).
        let frames = Frames::with(0x1000, &patched());
        frames.put(0x2000, &NTCLOSE);
        frames.put(0x3000, &patched());

        let repair = SiteJournal::repair_orphaned(&dir.0, "other", BASE, &frames, INT3);

        assert_eq!(
            repair,
            Repair {
                restored: 1,
                failed: 0
            }
        );
        assert_eq!(frames.get(0x1000, 8), NTCLOSE);
        assert_eq!(frames.get(0x3000, 8), patched());
        assert_eq!(
            fs::read_to_string(dir.0.join("other")).unwrap(),
            format!("{BASE:x} 2000 {bytes}\n{other_boot:x} 3000 {bytes}\n")
        );
    }

    #[test]
    fn the_window_stops_at_the_page_end() {
        assert_eq!(site_window(0x1ffd, &NTCLOSE), &NTCLOSE[..3]);
        assert_eq!(site_window(0x1000, &NTCLOSE), &NTCLOSE);
    }
}
