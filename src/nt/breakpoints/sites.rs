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
    /// (kernel code) under every address space.
    pub fn mask(&self, debugger: &Target, start: VirtAddr, buf: &mut [u8], dtb: Dtb) {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        let end = start.0.wrapping_add(buf.len() as u64);
        for site in &sites.breakpoints {
            if site.address.0 >= start.0
                && site.address.0 < end
                && site_in_view(debugger, site.address, site.process, dtb)
            {
                overlay(buf, start, site.address, site.original.as_slice());
            }
        }
        for (address, original) in sites.traps.iter().flatten() {
            if address.0 >= start.0 {
                overlay(buf, start, *address, original.as_slice());
            }
        }
    }
}

/// Copy `original`, the code at `address`, over its place in `buf` read at
/// `start`, when all of it falls inside.
fn overlay(buf: &mut [u8], start: VirtAddr, address: VirtAddr, original: &[u8]) {
    let offset = address.0 - start.0;
    if let Ok(offset) = usize::try_from(offset)
        && let Some(slot) = buf.get_mut(offset..offset.saturating_add(original.len()))
    {
        slot.copy_from_slice(original);
    }
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
