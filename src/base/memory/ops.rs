use std::sync::Arc;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::base::error::Result;
use crate::base::memory::{CompressedPages, PAGE_SIZE, SectionViews, TranslationCache};
use crate::base::types::{Dtb, VirtAddr};

/// Where a software PTE's page-file number starts on kernels with the L1TF
/// mitigation; see [`MemoryOps::page_file_low`].
pub const PAGE_FILE_LOW: u32 = 12;

/// Reads and writes of guest memory at addresses of type `A`: physical
/// memory ([`crate::backend::phys::PhysMem`]), or a virtual address space walked
/// through its page tables ([`crate::base::memory::AddressSpace`]).
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

    /// Write through the target in `root`, preserving guest write protection,
    /// copy-on-write, and residency handling. `None` requests a physical-write fallback.
    fn write_virtual_direct(&self, _addr: VirtAddr, _root: Dtb, _buf: &[u8]) -> Option<Result<()>> {
        None
    }

    /// Whether the target can service writes now. Request/reply transports
    /// require a halted target; a running target may need host-memory writes.
    fn can_mediate_writes(&self) -> bool {
        false
    }

    /// Translations the page walk may reuse across address-space instances.
    /// `None` when the backend cannot tell when the target's page tables
    /// change, which is every backend but a halted KD target.
    fn translation_cache(&self) -> Option<&TranslationCache> {
        None
    }

    /// Read a page-table entry's bytes. Page tables are RAM the target's
    /// own walker reads, so a backend may fetch a whole run of entries and
    /// keep them for as long as the tables cannot change; an arbitrary
    /// physical read gets no such read-ahead, since it may touch a device.
    fn read_page_table_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()> {
        self.read_bytes(addr, buf)
    }

    /// The bits the guest sets in a non-present page-table entry to point it
    /// at no real memory (Windows' L1TF mitigation, `InvalidPteMask`), which
    /// a transition entry's frame must have cleared; 0 when there are none.
    fn invalid_pte_mask(&self) -> u64 {
        0
    }

    /// The first bit of a software PTE's page-file number (`PageFileLow`):
    /// 12 on kernels with the L1TF mitigation (Windows 10 1809, and 1703 to
    /// 1803 from their 2018 updates), 1 before.
    fn page_file_low(&self) -> u32 {
        PAGE_FILE_LOW
    }

    /// A page of the memory-compression store this backend decompressed
    /// earlier while the guest has been halted, by its page-file number and
    /// page (`file << 32 | offset`); see [`Self::cache_store_page`].
    fn cached_store_page(&self, _key: u64) -> Option<Arc<[u8; PAGE_SIZE]>> {
        None
    }

    /// Keep a page decompressed from the memory-compression store until the
    /// guest runs again; a backend that cannot tell when it runs keeps none.
    fn cache_store_page(&self, _key: u64, _page: Arc<[u8; PAGE_SIZE]>) {}

    /// The guest's mapped views, for pages a process's page tables do not
    /// map (see [`SectionViews`]); `None` until a kernel is found.
    fn section_views(&self) -> Option<Arc<SectionViews>> {
        None
    }

    /// The guest's memory-compression store, for pages whose PTE is in the
    /// store's page file (see [`CompressedPages`]); `None` when the guest has
    /// none or its layout is not known.
    fn compressed_pages(&self) -> Option<Arc<CompressedPages>> {
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
/// so owners such as `Image` can share physical memory without changing
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

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        (**self).write_virtual_direct(addr, root, buf)
    }

    fn can_mediate_writes(&self) -> bool {
        (**self).can_mediate_writes()
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        (**self).translation_cache()
    }

    fn read_page_table_bytes(&self, addr: A, buf: &mut [u8]) -> Result<()> {
        (**self).read_page_table_bytes(addr, buf)
    }

    fn invalid_pte_mask(&self) -> u64 {
        (**self).invalid_pte_mask()
    }

    fn page_file_low(&self) -> u32 {
        (**self).page_file_low()
    }

    fn cached_store_page(&self, key: u64) -> Option<Arc<[u8; PAGE_SIZE]>> {
        (**self).cached_store_page(key)
    }

    fn cache_store_page(&self, key: u64, page: Arc<[u8; PAGE_SIZE]>) {
        (**self).cache_store_page(key, page);
    }

    fn section_views(&self) -> Option<Arc<SectionViews>> {
        (**self).section_views()
    }

    fn compressed_pages(&self) -> Option<Arc<CompressedPages>> {
        (**self).compressed_pages()
    }
}
