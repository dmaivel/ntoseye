//! A record of the breakpoint instructions this debugger wrote into guest
//! memory itself (host-patched user-space sites), kept on disk so a session
//! that dies without restoring them, killed or crashed, is repaired by the
//! next attach to the same target instead of leaving a trap in code every
//! process shares.
//!
//! Target-owned sites need none of this: the target keeps its own table and
//! a later session reclaims it.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::backend::MemoryOps;
use crate::memory::PAGE_SIZE;
use crate::types::PhysAddr;

/// Original bytes kept per site, starting at the patched address: the
/// displaced instruction bytes, then untouched bytes that tell the same code
/// apart from a frame the guest has since reused.
const WINDOW: usize = 8;

/// A patched site: the original bytes from the site's physical address to
/// the end of the window or the page, whichever comes first.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    original: Vec<u8>,
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
        let sites = fs::read_to_string(&path)
            .map(|text| parse(&text, kernel_base))
            .unwrap_or_default();
        let journal = Self {
            path,
            state: Mutex::new(State { kernel_base, sites }),
        };
        journal.persist(&journal.state());
        journal
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a site before its breakpoint instruction is written, with the
    /// original bytes from `address` to the end of the window or page.
    pub fn record(&self, address: PhysAddr, original: &[u8]) {
        let mut state = self.state();
        state.sites.insert(
            address,
            Site {
                original: original.to_vec(),
            },
        );
        self.persist(&state);
    }

    /// Forget a site whose original bytes are back in guest memory.
    pub fn forget(&self, address: PhysAddr) {
        let mut state = self.state();
        if state.sites.remove(&address).is_some() {
            self.persist(&state);
        }
    }

    /// Start over for a new boot: every recorded site went with the old
    /// memory. A reload that found the same kernel keeps them.
    pub fn rebase(&self, kernel_base: u64) {
        let mut state = self.state();
        if state.kernel_base != kernel_base {
            state.kernel_base = kernel_base;
            state.sites.clear();
            self.persist(&state);
        }
    }

    /// Put back every site a previous session left patched. A site is only
    /// written when its frame still holds `opcode` followed by exactly the
    /// bytes recorded after it; anything else means the guest restored it or
    /// reused the frame, and the entry is dropped untouched.
    pub fn repair(&self, memory: &impl MemoryOps<PhysAddr>, opcode: &[u8]) -> Repair {
        let mut state = self.state();
        let mut repair = Repair::default();
        let sites: Vec<(u64, Site)> = state
            .sites
            .iter()
            .map(|(address, site)| (*address, site.clone()))
            .collect();
        for (address, site) in sites {
            let mut current = vec![0u8; site.original.len()];
            let still_patched = site.original.len() >= opcode.len()
                && memory.read_bytes(address, &mut current).is_ok()
                && current[..opcode.len()] == *opcode
                && current[opcode.len()..] == site.original[opcode.len()..];
            if !still_patched {
                state.sites.remove(&address);
                continue;
            }
            match memory.write_bytes(address, &site.original[..opcode.len()]) {
                Ok(()) => {
                    state.sites.remove(&address);
                    repair.restored += 1;
                }
                Err(_) => repair.failed += 1,
            }
        }
        self.persist(&state);
        repair
    }

    /// Mirror the state to disk, replacing the file in one rename so a crash
    /// mid-write leaves the previous record rather than a torn one. An empty
    /// journal removes the file. Persistence is best effort: a journal that
    /// cannot be written costs the repair after a crash, not the breakpoint.
    fn persist(&self, state: &State) {
        if state.sites.is_empty() {
            let _ = fs::remove_file(&self.path);
            return;
        }
        let mut text = String::new();
        for (address, site) in &state.sites {
            let bytes: String = site.original.iter().map(|b| format!("{b:02x}")).collect();
            text.push_str(&format!("{:x} {address:x} {bytes}\n", state.kernel_base));
        }
        let staging = self.path.with_extension("tmp");
        let written = fs::File::create(&staging).and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        });
        if written.is_ok() {
            let _ = fs::rename(&staging, &self.path);
        }
    }
}

/// The window of original bytes to record for a site at `address` whose
/// bytes from there are `bytes`: at most [`WINDOW`], never past the page.
pub fn site_window(address: PhysAddr, bytes: &[u8]) -> &[u8] {
    let to_page_end = PAGE_SIZE - (address as usize & (PAGE_SIZE - 1));
    &bytes[..bytes.len().min(WINDOW).min(to_page_end)]
}

/// Parse `<kernel base> <physical address> <original bytes>` lines, keeping
/// the sites of the boot at `kernel_base`.
fn parse(text: &str, kernel_base: u64) -> BTreeMap<u64, Site> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let base = u64::from_str_radix(fields.next()?, 16).ok()?;
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let hex = fields.next()?;
            let original = (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            (base == kernel_base && !original.is_empty()).then_some((address, Site { original }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;
    use crate::error::{Error, Result};

    const INT3: &[u8] = &[0xcc];
    const BASE: u64 = 0xfffff805_afbc0000;

    /// Physical memory as a sparse byte map; `read_only` fails every write.
    #[derive(Default)]
    struct Frames {
        bytes: RefCell<HashMap<u64, u8>>,
        read_only: bool,
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

    /// The case a killed session leaves: a site recorded, never restored.
    fn stranded(dir: &Dir, address: u64) {
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        journal.record(address, &NTCLOSE);
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

    #[test]
    fn a_site_restored_cleanly_is_forgotten() {
        let dir = Dir::new("forget");
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        journal.record(0x1000, &NTCLOSE);
        journal.record(0x2000, &NTCLOSE);
        journal.forget(0x1000);
        drop(journal);

        let frames = Frames::with(0x1000, &patched());
        frames.put(0x2000, &patched());
        let journal = SiteJournal::open(&dir.0, "target", BASE);
        assert_eq!(journal.repair(&frames, INT3).restored, 1);
        assert_eq!(frames.get(0x1000, 8), patched());
        assert_eq!(frames.get(0x2000, 8), NTCLOSE);
    }

    #[test]
    fn the_window_stops_at_the_page_end() {
        assert_eq!(site_window(0x1ffd, &NTCLOSE), &NTCLOSE[..3]);
        assert_eq!(site_window(0x1000, &NTCLOSE), &NTCLOSE);
    }
}
