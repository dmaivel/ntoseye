use std::sync::Arc;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::error::Result;
use crate::memory::TranslationCache;
use crate::types::{Dtb, VirtAddr};

pub trait MemoryOps<A> {
    fn read_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()>;

    fn write_bytes(&self, addr: A, buf: &[u8]) -> Result<()>;

    /// Read guest virtual memory resolved by the backend itself when it can
    /// do so under `root`; `None` leaves the read to the host page walk. A
    /// live KD target resolves kernel space this way, which costs one
    /// request per chunk instead of a page-table walk plus one per page.
    fn read_virtual_direct(
        &self,
        _addr: VirtAddr,
        _root: Dtb,
        _buf: &mut [u8],
    ) -> Option<Result<()>> {
        None
    }

    /// Translations the page walk may reuse across address-space instances.
    /// `None` when the backend cannot tell when the target's page tables
    /// change, which is every backend but a halted KD target.
    fn translation_cache(&self) -> Option<&TranslationCache> {
        None
    }

    fn read<T: Copy + FromZeros + FromBytes + IntoBytes>(&self, addr: A) -> Result<T> {
        let mut obj = T::new_zeroed();

        let slice = obj.as_mut_bytes();
        self.read_bytes(addr, slice)?;

        Ok(obj)
    }

    fn write<T: Copy + IntoBytes + Immutable>(&self, addr: A, val: &T) -> Result<()> {
        let slice = val.as_bytes();
        self.write_bytes(addr, slice)
    }
}

/// Lets a shared `Arc<B>` stand in anywhere a memory backend `B` is expected,
/// so owners such as `WinObject` can share physical memory without changing
/// every reader signature.
impl<A, B: MemoryOps<A>> MemoryOps<A> for Arc<B> {
    fn read_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()> {
        (**self).read_bytes(addr, buf)
    }

    fn write_bytes(&self, addr: A, buf: &[u8]) -> Result<()> {
        (**self).write_bytes(addr, buf)
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        (**self).read_virtual_direct(addr, root, buf)
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        (**self).translation_cache()
    }
}
