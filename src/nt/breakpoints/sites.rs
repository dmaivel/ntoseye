//! Where the debugger's sites are in guest memory and the code they
//! displaced, published by their owners (the breakpoint manager and the
//! session's traps) for every read of guest memory to mask back.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, PoisonError, RwLock};

use super::install::{BreakpointPatch, site_in_view};
use crate::base::types::{Dtb, VirtAddr};
use crate::nt::target::Target;

/// The debugger-owned sites in guest memory, as their owners last published
/// them through [`Published`]. A target reads through them
/// ([`Target::mask_code`]), so an expression, a breakpoint condition and a
/// memory view all see the code the guest runs rather than the debugger's
/// breakpoint instruction. Each target has its own: a partition view's
/// holds none, since its breakpoints are debug registers.
#[derive(Default)]
pub struct CodeSites {
    sites: RwLock<Sites>,
}

#[derive(Default)]
struct Sites {
    breakpoints: Vec<PlantedSite>,
    /// The session's traps, by [`TrapKind`].
    traps: [Vec<(VirtAddr, BreakpointPatch)>; 2],
}

/// A breakpoint's site: where it is, the process whose address space it
/// was planted in (`None`: the kernel's), and the instruction it displaced.
pub struct PlantedSite {
    pub address: VirtAddr,
    pub process: Option<Dtb>,
    pub original: BreakpointPatch,
}

/// Which of the session's traps [`CodeSites::publish_traps`] replaces.
#[derive(Clone, Copy)]
pub enum TrapKind {
    Bugcheck,
    Module,
}

impl CodeSites {
    /// Replace the breakpoint manager's sites with `planted`.
    pub fn publish_breakpoints(&self, planted: impl Iterator<Item = PlantedSite>) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        sites.breakpoints.clear();
        sites.breakpoints.extend(planted);
    }

    /// Replace the `kind` traps with `traps`: each one's kernel address and
    /// the code it displaced, empty when its page was not resident.
    pub fn publish_traps<'a>(
        &self,
        kind: TrapKind,
        traps: impl Iterator<Item = (VirtAddr, &'a [u8])>,
    ) {
        let mut sites = self.sites.write().unwrap_or_else(PoisonError::into_inner);
        let published = &mut sites.traps[kind as usize];
        published.clear();
        published.extend(traps.filter_map(|(address, original)| {
            Some((address, BreakpointPatch::from_slice(original)?))
        }));
    }

    /// Put the code every site displaced back into `buf`, read at `start` in
    /// the address space `dtb` of `debugger`: a breakpoint's where the read
    /// reaches the frame it was written into ([`site_in_view`]), a trap's
    /// where it reaches the kernel's frame. A site the read covers only part
    /// of has that part put back: ARM64's breakpoint is four bytes, so a
    /// one-byte read can land inside it.
    pub fn mask(&self, debugger: &Target, start: VirtAddr, buf: &mut [u8], dtb: Dtb) {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        for site in &sites.breakpoints {
            let original = site.original.as_slice();
            if overlaps(start, buf.len(), site.address, original.len())
                && site_in_view(debugger, site.address, site.process, dtb)
            {
                overlay(buf, start, site.address, original);
            }
        }
        for (address, original) in sites.traps.iter().flatten() {
            let original = original.as_slice();
            if overlaps(start, buf.len(), *address, original.len())
                && site_in_view(debugger, *address, None, dtb)
            {
                overlay(buf, start, *address, original);
            }
        }
    }
}

/// Whether `len` bytes at `start` and a site of `site_len` bytes at
/// `address` share a byte.
pub fn overlaps(start: VirtAddr, len: usize, address: VirtAddr, site_len: usize) -> bool {
    address.0 < start.0.saturating_add(len as u64)
        && start.0 < address.0.saturating_add(site_len as u64)
}

/// Copy the part of `original`, the code at `address`, that falls inside
/// `buf`, read at `start`, over its place there.
fn overlay(buf: &mut [u8], start: VirtAddr, address: VirtAddr, original: &[u8]) {
    // Skip the site's bytes before the read, then the read's before the site.
    let skipped = usize::try_from(start.0.saturating_sub(address.0)).unwrap_or(usize::MAX);
    let offset = usize::try_from(address.0.saturating_sub(start.0)).unwrap_or(usize::MAX);
    let original = original.get(skipped..).unwrap_or_default();
    let buf = buf.get_mut(offset..).unwrap_or_default();
    let len = original.len().min(buf.len());
    buf[..len].copy_from_slice(&original[..len]);
}

/// An owner of debugger sites that a [`Published`] value republishes after
/// every change.
pub trait Publish {
    /// Replace this owner's sites in `sites` with the ones it holds now.
    fn publish(&self, sites: &CodeSites);
}

/// A value holding debugger sites (the breakpoint manager, a session's
/// traps), whose every change is published to its target's [`CodeSites`].
/// It is read freely; it is changed only through [`Self::edit`], whose guard
/// publishes when it is dropped, so what reads mask cannot drift from what
/// the owner has planted.
pub struct Published<T: Publish> {
    value: T,
    sites: Arc<CodeSites>,
}

impl<T: Publish> Published<T> {
    /// `value`, published to `sites` (a target's [`Target::code_sites`]).
    pub fn new(value: T, sites: Arc<CodeSites>) -> Self {
        value.publish(&sites);
        Self { value, sites }
    }

    /// Change the value; the change is published when the guard drops.
    pub fn edit(&mut self) -> Edit<'_, T> {
        Edit {
            value: &mut self.value,
            sites: &self.sites,
        }
    }
}

impl<T: Publish> Deref for Published<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

/// A change to a [`Published`] value, published when dropped.
pub struct Edit<'a, T: Publish> {
    value: &'a mut T,
    sites: &'a CodeSites,
}

impl<T: Publish> Deref for Edit<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value
    }
}

impl<T: Publish> DerefMut for Edit<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}

impl<T: Publish> Drop for Edit<'_, T> {
    fn drop(&mut self) {
        self.value.publish(self.sites);
    }
}

#[cfg(test)]
mod tests {
    use super::{overlaps, overlay};
    use crate::base::types::VirtAddr;

    /// ARM64's `brk #0xF000` over `original`, at 0x1000 in a read that
    /// starts at `start` and is `len` bytes long, masked.
    fn masked(start: u64, len: usize) -> Vec<u8> {
        let original = [0xa1, 0xb2, 0xc3, 0xd4];
        let brk = [0x00, 0x00, 0x3e, 0xd4, 0xee, 0xee];
        let site = VirtAddr(0x1000);
        // Guest memory from 0xffe: two bytes of other code, the brk, more code.
        let memory = [[0xee, 0xee].as_slice(), &brk].concat();
        let offset = usize::try_from(start - 0xffe).unwrap();
        let mut buf = memory[offset..offset + len].to_vec();
        if overlaps(VirtAddr(start), len, site, original.len()) {
            overlay(&mut buf, VirtAddr(start), site, &original);
        }
        buf
    }

    #[test]
    fn a_read_covering_part_of_a_site_sees_that_part_of_the_original() {
        assert_eq!(masked(0x1000, 1), [0xa1]);
        assert_eq!(masked(0x1000, 2), [0xa1, 0xb2]);
        assert_eq!(masked(0x1001, 1), [0xb2]);
        assert_eq!(masked(0x1002, 4), [0xc3, 0xd4, 0xee, 0xee]);
        assert_eq!(masked(0xfff, 3), [0xee, 0xa1, 0xb2]);
        assert_eq!(
            masked(0xffe, 8),
            [0xee, 0xee, 0xa1, 0xb2, 0xc3, 0xd4, 0xee, 0xee]
        );
    }

    #[test]
    fn a_read_beside_a_site_is_left_alone() {
        assert!(!overlaps(VirtAddr(0xffe), 2, VirtAddr(0x1000), 4));
        assert!(!overlaps(VirtAddr(0x1004), 2, VirtAddr(0x1000), 4));
        assert!(overlaps(VirtAddr(0x1003), 1, VirtAddr(0x1000), 4));
        assert_eq!(masked(0x1004, 2), [0xee, 0xee]);
    }
}
