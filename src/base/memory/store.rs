//! Reading a page from the memory-compression store, as the kernel's store
//! manager finds it: the page's key leads through the manager's key tree
//! to a store, through the store's pages tree to a region key, and through
//! the store's page records to a region and the offset in it of the page's
//! compressed bytes.

use super::{AddressSpace, MemoryOps, PAGE_SIZE, store_tree};
use crate::base::error::{Error, Result};
use crate::base::types::{Dtb, PhysAddr, VirtAddr};

/// Which chunk-pointer slot, and which 16-byte entry in that chunk, hold the
/// page records of `key`: the key shifted right by `shift` has its highest
/// set bit as the slot, and the rest of its bits as the entry.
pub fn chunk_entry(key: u32, shift: u32) -> Option<(usize, u64)> {
    let encoded = key.checked_shr(shift & 0xff)?;
    let slot = encoded.checked_ilog2()?;
    Some((slot as usize, u64::from(encoded ^ (1 << slot)) * 16))
}

/// A record key's region index and byte offset in that region: the key
/// shifted right by `shift`, and the key's bits under `mask` in 16-byte
/// units.
pub fn region_location(key: u32, shift: u32, mask: u32) -> Option<(u64, u64)> {
    Some((
        u64::from(key.checked_shr(shift & 0xff)?),
        u64::from(key & mask) << 4,
    ))
}

/// The field at `offset` in the structure at `base`.
fn field(base: VirtAddr, offset: u32) -> VirtAddr {
    base + u64::from(offset)
}

/// The address of the page record of region key `key` in the `ST_STORE` at
/// `st`: in the chunk its key picks from the chunk-pointer array, past the
/// chunk's header by the key's index.
pub fn page_record(
    memory: &impl MemoryOps<VirtAddr>,
    st: VirtAddr,
    layout: &StoreLayout,
    key: u32,
) -> Result<VirtAddr> {
    let fields = layout.chunk_fields;
    let shift: u32 = memory.read(field(st, fields.shift))?;
    let mask: u32 = memory.read(field(st, fields.mask))?;
    let size: u32 = memory.read(field(st, fields.record_size))?;
    let header: u32 = memory.read(field(st, fields.header))?;
    let no_chunk = || Error::DebugInfo(format!("store key {key:#x}: no chunk"));
    let (slot, entry) = chunk_entry(key, shift).ok_or_else(no_chunk)?;
    let chunk: u64 = memory.read(field(st, layout.chunk_array) + slot as u64 * 8)?;
    if chunk == 0 {
        return Err(no_chunk());
    }
    let records: u64 = memory.read(VirtAddr(chunk + entry))?;
    Ok(VirtAddr(records + u64::from(header)) + u64::from(size) * u64::from(key & mask))
}

/// Redirects a page's records are followed through at most.
const MAX_REDIRECTS: usize = 32;

/// The key and size word (the dword at +4) in the page record that region
/// key `key` leads to, following records that redirect to another key (key
/// `0xffffffff`, the next key at the layout's `redirect_next`).
pub fn resolve_record(
    memory: &impl MemoryOps<VirtAddr>,
    st: VirtAddr,
    layout: &StoreLayout,
    key: u32,
) -> Result<(u32, u32)> {
    let mut key = key;
    for _ in 0..=MAX_REDIRECTS {
        let record = page_record(memory, st, layout, key)?;
        let record_key: u32 = memory.read(record)?;
        if record_key != u32::MAX {
            return Ok((record_key, memory.read(record + 4u64)?));
        }
        let next: u32 = memory.read(field(record, layout.redirect_next))?;
        if next == key {
            break;
        }
        key = next;
    }
    Err(Error::DebugInfo(format!(
        "store key {key:#x}: page records redirect in a loop"
    )))
}

/// The address of region `index` of the `SMKM_STORE` at `store`, from its
/// region array. When the store's virtual flag is set, the entry is the
/// region's address with state bits; otherwise it points to a descriptor
/// with the address at +0x18.
pub fn region_address(
    memory: &impl MemoryOps<VirtAddr>,
    store: VirtAddr,
    layout: &StoreLayout,
    index: u64,
) -> Result<VirtAddr> {
    let array: u64 = memory.read(field(store, layout.region_array))?;
    let entry: u64 = memory.read(VirtAddr(array + index * 8))?;
    let (flag, bit) = layout.virtual_flag;
    let flags: u8 = memory.read(field(store, flag))?;
    if flags & (1 << bit) != 0 {
        return Ok(VirtAddr(entry & 0x7fff_ffff_ffff_0000));
    }
    memory.read(VirtAddr((entry & !7) + 0x18))
}

/// Set in a key-tree value whose key has no store behind it; the kernel's
/// lookup skips it too.
const NO_STORE: u32 = 0x0100_0000;
/// A key-tree value's store index: its high five bits pick a row of the
/// manager's 32 x 32 table, its low five bits an entry in that row.
const STORE_INDEX: u32 = 0x3ff;
/// Bytes of an entry of the manager's store table, which starts with the
/// store.
const STORE_ENTRY: u64 = 0x28;

/// The `SMKM_STORE` that holds page `key`, from the key tree of the store
/// manager at `manager` (its root pointer at `key_tree`); `None` when no
/// store holds the key.
pub fn store_for_key(
    memory: &impl MemoryOps<VirtAddr>,
    manager: VirtAddr,
    key_tree: u32,
    key: u32,
) -> Result<Option<VirtAddr>> {
    let root: u64 = memory.read(field(manager, key_tree))?;
    let Some(value) = store_tree::search(memory, root, key)? else {
        return Ok(None);
    };
    if value & NO_STORE != 0 {
        return Ok(None);
    }
    let index = u64::from(value & STORE_INDEX);
    let row: u64 = memory.read(manager + (index >> 5) * 8)?;
    if row == 0 {
        return Ok(None);
    }
    let store: u64 = memory.read(VirtAddr(row + (index & 0x1f) * STORE_ENTRY))?;
    Ok((store != 0).then_some(VirtAddr(store)))
}

/// The `ST_STORE` embedded in the `SMKM_STORE` at `store`: the offset (0x40
/// on 26H1, 0x50 before it; others nearby are tried) whose back pointer at
/// `back_pointer` points to `store`.
pub fn embedded_store(
    memory: &impl MemoryOps<VirtAddr>,
    store: VirtAddr,
    back_pointer: u32,
) -> Result<VirtAddr> {
    (0x40..=0x60u64)
        .step_by(8)
        .map(|offset| store + offset)
        .find(|&st| memory.read::<u64>(field(st, back_pointer)).ok() == Some(store.0))
        .ok_or_else(|| {
            Error::DebugInfo(format!(
                "store {store:#x}: no embedded ST_STORE points back to it"
            ))
        })
}

/// `COMPRESSION_FORMAT_XPRESS`, plain LZ77.
const FORMAT_XPRESS: u16 = 3;

/// Decompress one page's `data` from the store at `store` (its `ST_STORE`
/// at `st`) into `page`, by `compression`. Data of a page's size is the page
/// as it is.
pub fn decompress_page(
    memory: &impl MemoryOps<VirtAddr>,
    compression: Compression,
    store: VirtAddr,
    st: VirtAddr,
    data: &[u8],
    page: &mut [u8; PAGE_SIZE],
) -> Result<()> {
    if data.len() == page.len() {
        page.copy_from_slice(data);
        return Ok(());
    }
    match compression {
        Compression::FormatField(format) => match memory.read::<u16>(field(st, format))? {
            FORMAT_XPRESS => crate::base::decompress::xpress(data, page),
            other => Err(Error::DebugInfo(format!(
                "store {store:#x}: compression format {other} is not supported"
            ))),
        },
        Compression::Lz4UnlessCount(count) => match memory.read::<u32>(field(store, count))? {
            0 => crate::base::decompress::lz4(data, page),
            other => Err(Error::DebugInfo(format!(
                "store {store:#x}: a list of {other} compression algorithms is not supported"
            ))),
        },
    }
}

/// Where the store keeps what a page lookup needs. `SMKM_STORE` offsets are
/// from the store; `ST_STORE` offsets are from the store's embedded
/// `ST_STORE` (see [`embedded_store`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLayout {
    /// `SMKM_STORE`: the process whose address space holds the regions.
    pub owner_process: u32,
    /// `SMKM_STORE`: the pointer to the array of region entries.
    pub region_array: u32,
    /// `SMKM_STORE`: the byte and bit set when regions are virtual.
    pub virtual_flag: (u32, u8),
    /// `ST_STORE`: the pointer back to the store that embeds it.
    pub back_pointer: u32,
    /// `ST_STORE`: the shift that takes a region key to its region index.
    pub region_shift: u32,
    /// `ST_STORE`: the mask that takes a region key to its offset in the
    /// region, in 16-byte units.
    pub region_offset_mask: u32,
    /// `ST_STORE`: the array of chunk pointers that page records live in.
    pub chunk_array: u32,
    pub chunk_fields: ChunkFields,
    /// `SMKM_STORE_MGR`: the tree from page key to store index.
    pub key_tree: u32,
    /// `ST_STORE`: the tree from page key to region key.
    pub pages_tree: u32,
    /// Page record: where a redirecting record (key `0xffffffff`) keeps the
    /// key it redirects to; +4 to 26100, +8 from 28000.
    pub redirect_next: u32,
    pub compression: Compression,
}

/// The `ST_STORE` fields that place a page record in its chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkFields {
    /// The shift that takes a region key to its chunk slot and entry.
    pub shift: u32,
    /// The mask that takes a region key to its record in the chunk.
    pub mask: u32,
    /// The bytes of a record.
    pub record_size: u32,
    /// The bytes before a chunk's first record.
    pub header: u32,
}

/// How a store's pages are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Before 24H2: the `ST_STORE` word at this offset is the
    /// `RtlDecompressBuffer` format.
    FormatField(u32),
    /// From 24H2: LZ4 when the `SMKM_STORE` count at this offset is zero.
    Lz4UnlessCount(u32),
}

/// What reading a page from the memory-compression store needs besides its
/// PTE: the store layout, the store manager, the process that owns the
/// stores' regions, and the page-file number of the store's virtual page
/// file.
#[derive(Debug, Clone)]
pub struct CompressedPages {
    pub layout: StoreLayout,
    /// The `SMKM_STORE_MGR`.
    pub manager: VirtAddr,
    /// The owning process's `EPROCESS`, which each store names.
    pub owner: VirtAddr,
    /// The root of the owning process's address space.
    pub owner_root: Dtb,
    /// The page-file number that PTEs of store pages carry.
    pub page_file: u8,
}

impl CompressedPages {
    /// Page `offset` of the store's page file, decompressed into `page`.
    /// `space` reads the store manager and its stores; the regions are in
    /// the owning process's address space.
    pub fn read<B: MemoryOps<PhysAddr>>(
        &self,
        space: &AddressSpace<'_, B>,
        offset: u32,
        page: &mut [u8; PAGE_SIZE],
    ) -> Result<()> {
        let owner =
            AddressSpace::for_arch(space.backend, self.owner_root, space.kernel_dtb, space.arch);
        // Before 24H2 a page's key carries the page-file number in its top
        // four bits; from 24H2 it is the bare offset. A kernel's tree holds
        // one form, so both are tried.
        for key in [u32::from(self.page_file) << 28 | offset, offset] {
            if let Some(store) = store_for_key(space, self.manager, self.layout.key_tree, key)? {
                return self.read_key(space, &owner, store, key, page);
            }
        }
        Err(Error::DebugInfo(format!(
            "store page {offset:#x}: in no store"
        )))
    }

    /// Page `key` of the `SMKM_STORE` at `store`, decompressed into `page`:
    /// `kernel` reads the store, `regions` the address space of the process
    /// that owns it, which the store must name.
    pub fn read_key(
        &self,
        kernel: &impl MemoryOps<VirtAddr>,
        regions: &impl MemoryOps<VirtAddr>,
        store: VirtAddr,
        key: u32,
        page: &mut [u8; PAGE_SIZE],
    ) -> Result<()> {
        let layout = &self.layout;
        let fail = |what: &dyn std::fmt::Display| {
            Error::DebugInfo(format!("store page key {key:#x}: {what}"))
        };
        if kernel.read::<u64>(field(store, layout.owner_process))? != self.owner.0 {
            return Err(fail(&"its store belongs to another process"));
        }
        let st = embedded_store(kernel, store, layout.back_pointer)?;
        let pages: u64 = kernel.read(field(st, layout.pages_tree))?;
        let region_key = store_tree::search(kernel, pages, key)?
            .ok_or_else(|| fail(&"not in its store's pages"))?;
        let (record_key, size) = resolve_record(kernel, st, layout, region_key)?;
        let shift: u32 = kernel.read(field(st, layout.region_shift))?;
        let mask: u32 = kernel.read(field(st, layout.region_offset_mask))?;
        let (index, offset) =
            region_location(record_key, shift, mask).ok_or_else(|| fail(&"bad region shift"))?;
        let at = region_address(kernel, store, layout, index)? + offset;
        // The size word's low 12 bits are the compressed length, 0 for a
        // page kept as it is; the kernel keeps other state above them.
        let length = match size & 0xfff {
            0 => PAGE_SIZE,
            length => length as usize,
        };
        let mut data = [0u8; PAGE_SIZE];
        // The store's own pages can be paged out to disk, or left out of a
        // dump.
        regions.read_bytes(at, &mut data[..length]).map_err(|_| {
            fail(&format_args!(
                "its compressed data at {at:#x} is not in memory"
            ))
        })?;
        decompress_page(kernel, layout.compression, store, st, &data[..length], page)
    }
}

/// Test memory, and a whole store in it, for the tests of the store walk
/// and of the page walk through it.
#[cfg(test)]
pub mod fixture {
    use super::*;
    use std::collections::BTreeMap;

    /// Guest memory of bytes at fixed addresses; no other address reads.
    pub struct Bytes(BTreeMap<u64, u8>);

    impl Bytes {
        pub fn new<V: AsRef<[u8]>>(values: &[(u64, V)]) -> Self {
            Self(
                values
                    .iter()
                    .flat_map(|(at, data)| {
                        (data.as_ref().iter().enumerate())
                            .map(move |(i, &byte)| (at + i as u64, byte))
                    })
                    .collect(),
            )
        }
    }

    impl MemoryOps<VirtAddr> for Bytes {
        fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = *self
                    .0
                    .get(&(addr.0 + i as u64))
                    .ok_or(Error::BadVirtualAddress(addr))?;
            }
            Ok(())
        }

        fn write_bytes(&self, addr: VirtAddr, _: &[u8]) -> Result<()> {
            Err(Error::BadVirtualAddress(addr))
        }
    }

    /// The layout of 24H2 from 26100.9278 on.
    pub fn layout() -> StoreLayout {
        StoreLayout {
            owner_process: 0x1d00,
            region_array: 0x1b68,
            virtual_flag: (0x1a95, 2),
            back_pointer: 0x320,
            region_shift: 0x32c,
            region_offset_mask: 0x328,
            chunk_array: 0xc0,
            chunk_fields: ChunkFields {
                shift: 0x1c8,
                mask: 0x1cc,
                record_size: 0x1d0,
                header: 0x1d8,
            },
            key_tree: 0x1c0,
            pages_tree: 0,
            redirect_next: 4,
            compression: Compression::Lz4UnlessCount(0x12c0),
        }
    }

    pub const MANAGER: u64 = 0x100_000;
    pub const STORE: u64 = 0x200_000;
    pub const OWNER: u64 = 0xffff_8000_0000_1000;
    /// The page key the store holds: page 0x42 of page file 2.
    pub const KEY: u32 = 0x2000_0042;
    /// Where that page's compressed bytes are, in the owner's address
    /// space.
    pub const DATA_AT: u64 = 0x0123_0000_0200;

    /// Kernel memory where the key tree of the store manager at [`MANAGER`]
    /// leads [`KEY`] to the store at [`STORE`], owned by [`OWNER`], whose
    /// page record for it has `size` as its size word and its bytes at
    /// [`DATA_AT`].
    pub fn kernel_values(size: u32) -> Vec<(u64, Vec<u8>)> {
        let leaf = |key: u32, value: u32| store_tree::node(true, 0, &[(key, u64::from(value))]);
        let q = |value: u64| value.to_le_bytes().to_vec();
        let d = |value: u32| value.to_le_bytes().to_vec();
        let st = STORE + 0x50;
        let (region_key, record_key) = (1 << 8 | 2, 1 << 16 | 0x20);
        vec![
            (MANAGER + 0x1c0, q(0x110_000)),
            (0x110_000, leaf(KEY, 0)),
            (MANAGER, q(0x120_000)),
            (0x120_000, q(STORE)),
            (STORE + 0x1d00, q(OWNER)),
            (st + 0x320, q(STORE)),
            (STORE + 0x1b68, q(0x300_000)),
            (STORE + 0x1a95, vec![0b100]),
            (STORE + 0x12c0, d(0)),
            (st, q(0x130_000)),
            (0x130_000, leaf(KEY, region_key)),
            (st + 0x1c8, d(8)),
            (st + 0x1cc, d(0xff)),
            (st + 0x1d0, d(8)),
            (st + 0x1d8, d(0)),
            (st + 0xc0, q(0x140_000)),
            (0x140_000, q(0x150_000)),
            (0x150_010, d(record_key)),
            (0x150_014, d(size)),
            (st + 0x32c, d(16)),
            (st + 0x328, d(0xffff)),
            // Region 1, its address with state bits.
            (0x300_008, q((DATA_AT - 0x200) | 5)),
        ]
    }

    /// The pages of that store, the owner's address space at `owner_root`.
    pub fn pages(owner_root: Dtb) -> CompressedPages {
        CompressedPages {
            layout: layout(),
            manager: VirtAddr(MANAGER),
            owner: VirtAddr(OWNER),
            owner_root,
            page_file: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, Bytes, DATA_AT, KEY, MANAGER, STORE};
    use super::*;

    #[test]
    fn a_redirect_record_leads_to_the_page_and_a_loop_is_refused() {
        let st = VirtAddr(0x10_000);
        let first: u32 = 0b100 << 8;
        let second: u32 = 0b100 << 8 | 1;
        let mut values: Vec<(u64, Vec<u8>)> = vec![
            (st.0 + 0x1c8, 8u32.to_le_bytes().to_vec()),
            (st.0 + 0x1cc, 0xffu32.to_le_bytes().to_vec()),
            (st.0 + 0x1d0, 12u32.to_le_bytes().to_vec()),
            (st.0 + 0x1d8, 0u32.to_le_bytes().to_vec()),
            (st.0 + 0xc0 + 2 * 8, 0x20_000u64.to_le_bytes().to_vec()),
            (0x20_000, 0x30_000u64.to_le_bytes().to_vec()),
            // Record 0 redirects to record 1, which holds the page.
            (0x30_000, u32::MAX.to_le_bytes().to_vec()),
            (0x30_004, second.to_le_bytes().to_vec()),
            (0x30_000 + 12, 0x0005_0042u32.to_le_bytes().to_vec()),
            (0x30_000 + 16, 0x0123u32.to_le_bytes().to_vec()),
        ];
        let layout = fixture::layout();
        assert_eq!(
            resolve_record(&Bytes::new(&values), st, &layout, first).unwrap(),
            (0x0005_0042, 0x123)
        );
        // 28000 keeps the next key at +8, past the size word at +4.
        let mut moved = values.clone();
        moved[7].1 = 0x0000_0123u32.to_le_bytes().to_vec();
        moved.push((0x30_008, second.to_le_bytes().to_vec()));
        let layout_28000 = StoreLayout {
            redirect_next: 8,
            ..fixture::layout()
        };
        assert_eq!(
            resolve_record(&Bytes::new(&moved), st, &layout_28000, first).unwrap(),
            (0x0005_0042, 0x123)
        );
        // Record 0 redirecting to itself.
        values[7].1 = first.to_le_bytes().to_vec();
        assert!(resolve_record(&Bytes::new(&values), st, &layout, first).is_err());
    }

    #[test]
    fn a_region_entry_is_an_address_or_a_descriptor() {
        let store = VirtAddr(0x10_000);
        let layout = fixture::layout();
        let entry = |value: u64, flags: u8, descriptor: Option<u64>| {
            let mut values = vec![
                (store.0 + 0x1b68, 0x20_000u64.to_le_bytes().to_vec()),
                (0x20_000 + 3 * 8, value.to_le_bytes().to_vec()),
                (store.0 + 0x1a95, vec![flags]),
            ];
            values.extend(descriptor.map(|at| (0x30_000 + 0x18, at.to_le_bytes().to_vec())));
            region_address(&Bytes::new(&values), store, &layout, 3).unwrap()
        };
        assert_eq!(
            entry(0x0000_0123_4567_0005, 0b100, None),
            VirtAddr(0x0123_4567_0000)
        );
        assert_eq!(
            entry(0x30_003, 0, Some(0x0222_0000_0000)),
            VirtAddr(0x0222_0000_0000)
        );
    }

    #[test]
    fn a_page_key_leads_to_its_store_through_the_table() {
        let manager = VirtAddr(0x10_000);
        let memory = Bytes::new(&[
            (manager.0 + 0x1c0, 0x40_000u64.to_le_bytes().to_vec()),
            // Store index 33: row 1, entry 1.
            (0x40_000, store_tree::node(true, 0, &[(0x2000_1234, 33)])),
            (manager.0 + 8, 0x50_000u64.to_le_bytes().to_vec()),
            (0x50_000 + 0x28, 0x60_000u64.to_le_bytes().to_vec()),
        ]);
        assert_eq!(
            store_for_key(&memory, manager, 0x1c0, 0x2000_1234).unwrap(),
            Some(VirtAddr(0x60_000))
        );
        assert_eq!(
            store_for_key(&memory, manager, 0x1c0, 0x2000_1235).unwrap(),
            None
        );
    }

    #[test]
    fn the_embedded_store_is_the_one_that_points_back() {
        let store = VirtAddr(0x10_000);
        let memory = Bytes::new(&[
            // A pointer elsewhere at 0x40's back-pointer slot, the store at 0x50's.
            (store.0 + 0x40 + 0x320, 0x99_000u64.to_le_bytes()),
            (store.0 + 0x50 + 0x320, store.0.to_le_bytes()),
        ]);
        assert_eq!(
            embedded_store(&memory, store, 0x320).unwrap(),
            store + 0x50u64
        );
        assert!(embedded_store(&memory, store + 0x1000u64, 0x320).is_err());
    }

    #[test]
    fn a_page_decompresses_by_the_stores_algorithm() {
        let (store, st) = (VirtAddr(0x10_000), VirtAddr(0x10_050));
        let original: Vec<u8> = (0..4096u32).map(|i| (i / 64) as u8).collect();
        let decompress = |values: &[(u64, Vec<u8>)], compression, data: &[u8]| {
            let mut page = [0u8; PAGE_SIZE];
            decompress_page(&Bytes::new(values), compression, store, st, data, &mut page)
                .map(|()| page.to_vec())
        };
        // 24H2: LZ4 while the store's algorithm count is zero.
        let lz4 = lz4_flex::block::compress(&original);
        let zero = [(store.0 + 0x12c0, 0u32.to_le_bytes().to_vec())];
        assert_eq!(
            decompress(&zero, Compression::Lz4UnlessCount(0x12c0), &lz4).unwrap(),
            original
        );
        let listed = [(store.0 + 0x12c0, 2u32.to_le_bytes().to_vec())];
        assert!(decompress(&listed, Compression::Lz4UnlessCount(0x12c0), &lz4).is_err());
        // Before 24H2: the format field; XPRESS as literals only.
        let mut xpress = Vec::new();
        for group in original.chunks(32) {
            xpress.extend_from_slice(&[0; 4]);
            xpress.extend_from_slice(group);
        }
        xpress.extend_from_slice(&[0; 4]);
        let format = |value: u16| [(st.0 + 0x3e0, value.to_le_bytes().to_vec())];
        assert_eq!(
            decompress(&format(3), Compression::FormatField(0x3e0), &xpress).unwrap(),
            original
        );
        assert!(decompress(&format(4), Compression::FormatField(0x3e0), &xpress).is_err());
        // Stored as it is.
        assert_eq!(
            decompress(&[], Compression::FormatField(0x3e0), &original).unwrap(),
            original
        );
    }

    #[test]
    fn a_page_key_reads_back_its_page_through_the_whole_store() {
        let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let data = lz4_flex::block::compress(&original);
        let read = |pages: &CompressedPages, size: u32, stored: &[u8]| {
            let kernel = Bytes::new(&fixture::kernel_values(size));
            let regions = Bytes::new(&[(DATA_AT, stored)]);
            let store = store_for_key(&kernel, VirtAddr(MANAGER), 0x1c0, KEY)?.unwrap();
            assert_eq!(store, VirtAddr(STORE));
            let mut page = [0xccu8; PAGE_SIZE];
            pages
                .read_key(&kernel, &regions, store, KEY, &mut page)
                .map(|()| page.to_vec())
        };
        let pages = fixture::pages(0);
        assert_eq!(read(&pages, data.len() as u32, &data).unwrap(), original);
        // A size word whose low 12 bits are 0 holds the page as it is,
        // whatever the kernel keeps above them.
        assert_eq!(read(&pages, 0x5000, &original).unwrap(), original);
        // A store that names another owner is not read.
        let other = CompressedPages {
            owner: VirtAddr(fixture::OWNER + 8),
            ..fixture::pages(0)
        };
        assert!(read(&other, data.len() as u32, &data).is_err());
    }

    #[test]
    fn a_page_record_is_found_through_its_chunk() {
        let st = VirtAddr(0x10_000);
        let key = 0b101 << 8 | 0x03;
        let memory = Bytes::new(&[
            (st.0 + 0x1c8, 8u32.to_le_bytes().to_vec()),
            (st.0 + 0x1cc, 0xffu32.to_le_bytes().to_vec()),
            (st.0 + 0x1d0, 12u32.to_le_bytes().to_vec()),
            (st.0 + 0x1d8, 0x20u32.to_le_bytes().to_vec()),
            // Slot 2 (0b101's top bit), entry 1 (0b01).
            (st.0 + 0xc0 + 2 * 8, 0x20_000u64.to_le_bytes().to_vec()),
            (0x20_000 + 16, 0x30_000u64.to_le_bytes().to_vec()),
        ]);
        let record = page_record(&memory, st, &fixture::layout(), key).unwrap();
        assert_eq!(record, VirtAddr(0x30_000 + 0x20 + 12 * 3));
    }

    #[test]
    fn a_key_picks_its_slot_by_its_highest_bit() {
        // With the low 8 bits dropped: 0b1_0110 is slot 4, entry 0b0110.
        assert_eq!(chunk_entry(0b1_0110 << 8 | 0x7f, 8), Some((4, 6 * 16)));
        assert_eq!(chunk_entry(1 << 8, 8), Some((0, 0)));
        assert_eq!(chunk_entry(0xff, 8), None, "no bit above the shift");
    }

    #[test]
    fn a_region_key_splits_into_index_and_offset() {
        assert_eq!(region_location(0x0003_0021, 16, 0xffff), Some((3, 0x210)));
    }
}
