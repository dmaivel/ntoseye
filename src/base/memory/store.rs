//! Arithmetic the store does to find a page: a page record from a region
//! key, and a region and offset from a record's key, as the kernel's
//! `ST_PAGE_RECORD_GET` and page retrieval compute them.

/// Which chunk-pointer slot, and which 16-byte entry in that chunk, hold the
/// page records of `key`: the key shifted right by `shift` has its highest
/// set bit as the slot, and the rest of its bits as the entry.
pub fn chunk_entry(key: u32, shift: u32) -> Option<(usize, u64)> {
    let encoded = key.checked_shr(shift & 0xff)?;
    let slot = encoded.checked_ilog2()?;
    Some((slot as usize, u64::from(encoded ^ (1 << slot)) * 16))
}

/// The address of `key`'s page record, in the record array at `records`.
pub fn record_address(records: u64, key: u32, mask: u32, size: u32, header: u32) -> u64 {
    records + u64::from(header) + u64::from(size) * u64::from(key & mask)
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

/// A little-endian u64 read with `read` at `address`.
pub fn read_u64(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    address: u64,
) -> crate::base::error::Result<u64> {
    let mut bytes = [0u8; 8];
    read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// A little-endian u32 read with `read` at `address`.
pub fn read_u32(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    address: u64,
) -> crate::base::error::Result<u32> {
    let mut bytes = [0u8; 4];
    read(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// The address of the page record of region key `key` in the `ST_STORE` at
/// `st`, whose chunk-pointer array is at `chunk_array` and whose chunk
/// shift, records-per-chunk mask, record size and header size are at
/// `fields`.
pub fn page_record(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    st: u64,
    chunk_array: u32,
    fields: [u32; 4],
    key: u32,
) -> crate::base::error::Result<u64> {
    let [shift, mask, size, header] = fields;
    let shift = read_u32(read, st + u64::from(shift))?;
    let mask = read_u32(read, st + u64::from(mask))?;
    let size = read_u32(read, st + u64::from(size))?;
    let header = read_u32(read, st + u64::from(header))?;
    let bad = || crate::base::error::Error::DebugInfo(format!("store key {key:#x}: no chunk"));
    let (slot, entry) = chunk_entry(key, shift)
        .filter(|(slot, _)| *slot < 32)
        .ok_or_else(bad)?;
    let chunk = read_u64(read, st + u64::from(chunk_array) + slot as u64 * 8)?;
    if chunk == 0 {
        return Err(bad());
    }
    let records = read_u64(read, chunk + entry)?;
    Ok(record_address(records, key, mask, size, header))
}

/// Redirects a page's records are followed through at most.
const MAX_REDIRECTS: usize = 32;

/// The key and size word (the dword at +4) in the page record that region
/// key `key` leads to, following records that redirect to another key (key
/// `0xffffffff`, the next key at `redirect_next`).
pub fn resolve_record(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    st: u64,
    chunk_array: u32,
    fields: [u32; 4],
    redirect_next: u32,
    key: u32,
) -> crate::base::error::Result<(u32, u32)> {
    let mut key = key;
    for _ in 0..=MAX_REDIRECTS {
        let record = page_record(read, st, chunk_array, fields, key)?;
        let record_key = read_u32(read, record)?;
        if record_key != u32::MAX {
            return Ok((record_key, read_u32(read, record + 4)?));
        }
        let next = read_u32(read, record + u64::from(redirect_next))?;
        if next == key {
            break;
        }
        key = next;
    }
    Err(crate::base::error::Error::DebugInfo(format!(
        "store key {key:#x}: page records redirect in a loop"
    )))
}

/// The address of region `index` of the `SMKM_STORE` at `store`, from its
/// region array (the pointer at `region_array`). When the store's virtual
/// flag (`flag`, byte and bit) is set, the entry is the region's address
/// with state bits; otherwise it points to a descriptor with the address at
/// +0x18.
pub fn region_address(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    store: u64,
    region_array: u32,
    flag: (u32, u8),
    index: u64,
) -> crate::base::error::Result<u64> {
    let array = read_u64(read, store + u64::from(region_array))?;
    let entry = read_u64(read, array + index * 8)?;
    let mut flags = [0u8; 1];
    read(store + u64::from(flag.0), &mut flags)?;
    if flags[0] & (1 << flag.1) != 0 {
        return Ok(entry & 0x7fff_ffff_ffff_0000);
    }
    read_u64(read, (entry & !7) + 0x18)
}

/// The `SMKM_STORE` that holds page `key`: the manager's key tree (its root
/// pointer at `key_tree`) gives a store index, whose high five bits pick a
/// row of the manager's 32 x 32 table and low five bits a 40-byte entry in
/// it, which starts with the store. `None` when no store holds the key.
pub fn store_for_key(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    manager: u64,
    key_tree: u32,
    key: u32,
) -> crate::base::error::Result<Option<u64>> {
    let root = read_u64(read, manager + u64::from(key_tree))?;
    let Some(value) = super::store_tree::search(&mut *read, root, key)? else {
        return Ok(None);
    };
    if value & 0x0100_0000 != 0 {
        return Ok(None);
    }
    let index = u64::from(value & 0x3ff);
    let row = read_u64(read, manager + (index >> 5) * 8)?;
    if row == 0 {
        return Ok(None);
    }
    let store = read_u64(read, row + (index & 0x1f) * 0x28)?;
    Ok((store != 0).then_some(store))
}

/// The `ST_STORE` embedded in the `SMKM_STORE` at `store`: the offset (0x40
/// on 26H1, 0x50 before it; others nearby are tried) whose back pointer at
/// `back_pointer` points to `store`.
pub fn embedded_store(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    store: u64,
    back_pointer: u32,
) -> crate::base::error::Result<u64> {
    for offset in (0x40..=0x60).step_by(8) {
        let st = store + offset;
        if read_u64(read, st + u64::from(back_pointer)).ok() == Some(store) {
            return Ok(st);
        }
    }
    Err(crate::base::error::Error::DebugInfo(format!(
        "store {store:#x}: no embedded ST_STORE points back to it"
    )))
}

/// `COMPRESSION_FORMAT_XPRESS`, plain LZ77.
const FORMAT_XPRESS: u16 = 3;

/// Decompress one page's `data` from the store at `store` (its `ST_STORE`
/// at `st`) into `page`, by `compression`. Data of 4096 bytes is the page
/// as it is.
pub fn decompress_page(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    compression: Compression,
    store: u64,
    st: u64,
    data: &[u8],
    page: &mut [u8; 4096],
) -> crate::base::error::Result<()> {
    use crate::base::error::Error;
    if data.len() == page.len() {
        page.copy_from_slice(data);
        return Ok(());
    }
    match compression {
        Compression::FormatField(field) => {
            let mut format = [0u8; 2];
            read(st + u64::from(field), &mut format)?;
            match u16::from_le_bytes(format) {
                FORMAT_XPRESS => crate::base::decompress::xpress(data, page),
                other => Err(Error::DebugInfo(format!(
                    "store {store:#x}: compression format {other} is not supported"
                ))),
            }
        }
        Compression::Lz4UnlessCount(count) => match read_u32(read, store + u64::from(count))? {
            0 => crate::base::decompress::lz4(data, page),
            other => Err(Error::DebugInfo(format!(
                "store {store:#x}: a list of {other} compression algorithms is not supported"
            ))),
        },
    }
}

/// Page `key` of the memory-compression store, decompressed into `page`.
/// `kernel` reads the store manager (at `manager`) and its stores; `regions`
/// reads the address space of the process that owns them (`owner`, its
/// EPROCESS), which a store must name.
pub fn read_page(
    kernel: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    regions: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    layout: &StoreLayout,
    manager: u64,
    owner: u64,
    key: u32,
    page: &mut [u8; 4096],
) -> crate::base::error::Result<()> {
    use crate::base::error::Error;
    let fail = |what: &str| Error::DebugInfo(format!("store page key {key:#x}: {what}"));
    let store =
        store_for_key(kernel, manager, layout.key_tree, key)?.ok_or_else(|| fail("in no store"))?;
    if read_u64(kernel, store + u64::from(layout.owner_process))? != owner {
        return Err(fail("its store belongs to another process"));
    }
    let st = embedded_store(kernel, store, layout.back_pointer)?;
    let pages = read_u64(kernel, st + u64::from(layout.pages_tree))?;
    let region_key = super::store_tree::search(&mut *kernel, pages, key)?
        .ok_or_else(|| fail("not in its store's pages"))?;
    let (record_key, size) = resolve_record(
        kernel,
        st,
        layout.chunk_array,
        layout.chunk_fields,
        layout.redirect_next,
        region_key,
    )?;
    let shift = read_u32(kernel, st + u64::from(layout.region_shift))?;
    let mask = read_u32(kernel, st + u64::from(layout.region_offset_mask))?;
    let (index, offset) =
        region_location(record_key, shift, mask).ok_or_else(|| fail("bad region shift"))?;
    let region = region_address(
        kernel,
        store,
        layout.region_array,
        layout.virtual_flag,
        index,
    )?;
    // The size word's low 12 bits are the compressed length, 0 for a page
    // kept as it is; the kernel keeps other state above them.
    let length = match size & 0xfff {
        0 => 0x1000,
        length => length as usize,
    };
    let mut data = vec![0u8; length];
    // The store's own pages can be paged out to disk, or left out of a dump.
    regions(region + offset, &mut data).map_err(|_| {
        fail(&format!(
            "its compressed data at {:#x} is not in memory",
            region + offset
        ))
    })?;
    decompress_page(kernel, layout.compression, store, st, &data, page)
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
    /// `ST_STORE`: the chunk shift, records-per-chunk mask, record size and
    /// chunk header size.
    pub chunk_fields: [u32; 4],
    /// `SMKM_STORE_MGR`: the tree from page key to store index.
    pub key_tree: u32,
    /// `ST_STORE`: the tree from page key to region key.
    pub pages_tree: u32,
    /// Page record: where a redirecting record (key `0xffffffff`) keeps the
    /// key it redirects to; +4 to 26100, +8 from 28000.
    pub redirect_next: u32,
    pub compression: Compression,
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
    pub manager: u64,
    /// The owning process's `EPROCESS`, which each store names.
    pub owner: u64,
    /// The root of the owning process's address space.
    pub owner_root: crate::base::types::Dtb,
    /// The page-file number that PTEs of store pages carry.
    pub page_file: u8,
}

impl CompressedPages {
    /// The page whose non-present PTE in `space` is `pte`, when that PTE
    /// is in the store's page file; `None` for any other PTE.
    pub fn read<B: super::MemoryOps<crate::base::types::PhysAddr>>(
        &self,
        space: &super::AddressSpace<'_, B>,
        pte: crate::base::types::PageTableEntry,
        page: &mut [u8; 4096],
    ) -> Option<crate::base::error::Result<()>> {
        use super::MemoryOps;
        use crate::base::types::VirtAddr;
        if pte.is_present() || pte.is_prototype() || pte.is_transition() {
            return None;
        }
        let pte = pte.unswizzled(space.backend.invalid_pte_mask());
        let (page_file, offset) = pte.page_file_location(space.backend.page_file_low());
        if page_file != self.page_file || offset == 0 {
            return None;
        }
        let mut kernel = |address: u64, buf: &mut [u8]| space.read_bytes(VirtAddr(address), buf);
        let owner = super::AddressSpace::for_arch(
            space.backend,
            self.owner_root,
            space.kernel_dtb,
            space.arch,
        );
        let mut regions = |address: u64, buf: &mut [u8]| owner.read_bytes(VirtAddr(address), buf);
        // The key carries the page-file number in its top four bits before
        // 24H2 and not from it; a kernel's tree holds one form only.
        let with_file = u32::from(self.page_file) << 28 | offset;
        let key = match store_for_key(&mut kernel, self.manager, self.layout.key_tree, with_file) {
            Ok(Some(_)) => with_file,
            Ok(None) => offset,
            Err(error) => return Some(Err(error)),
        };
        Some(read_page(
            &mut kernel,
            &mut regions,
            &self.layout,
            self.manager,
            self.owner,
            key,
            page,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memory of little-endian values at fixed addresses.
    fn memory(
        values: &[(u64, &[u8])],
    ) -> impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()> + use<> {
        let bytes: std::collections::BTreeMap<u64, u8> = values
            .iter()
            .flat_map(|(at, data)| {
                data.iter()
                    .enumerate()
                    .map(move |(i, b)| (at + i as u64, *b))
            })
            .collect();
        move |address, out| {
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = *bytes.get(&(address + i as u64)).ok_or(
                    crate::base::error::Error::BadVirtualAddress(crate::base::types::VirtAddr(
                        address,
                    )),
                )?;
            }
            Ok(())
        }
    }

    #[test]
    fn a_redirect_record_leads_to_the_page_and_a_loop_is_refused() {
        let st = 0x10_000;
        let fields = [0x1c8, 0x1cc, 0x1d0, 0x1d8];
        let first: u32 = 0b100 << 8;
        let second: u32 = 0b100 << 8 | 1;
        let mut values: Vec<(u64, Vec<u8>)> = vec![
            (st + 0x1c8, 8u32.to_le_bytes().to_vec()),
            (st + 0x1cc, 0xffu32.to_le_bytes().to_vec()),
            (st + 0x1d0, 12u32.to_le_bytes().to_vec()),
            (st + 0x1d8, 0u32.to_le_bytes().to_vec()),
            (st + 0xc0 + 2 * 8, 0x20_000u64.to_le_bytes().to_vec()),
            (0x20_000, 0x30_000u64.to_le_bytes().to_vec()),
            // Record 0 redirects to record 1, which holds the page.
            (0x30_000, u32::MAX.to_le_bytes().to_vec()),
            (0x30_004, second.to_le_bytes().to_vec()),
            (0x30_000 + 12, 0x0005_0042u32.to_le_bytes().to_vec()),
            (0x30_000 + 16, 0x0123u32.to_le_bytes().to_vec()),
        ];
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            resolve_record(&mut read, st, 0xc0, fields, 4, first).unwrap(),
            (0x0005_0042, 0x123)
        );
        // 28000 keeps the next key at +8, past the size word at +4.
        let mut moved = values.clone();
        moved[7].1 = 0x0000_0123u32.to_le_bytes().to_vec();
        moved.push((0x30_008, second.to_le_bytes().to_vec()));
        let borrowed: Vec<(u64, &[u8])> = moved.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            resolve_record(&mut read, st, 0xc0, fields, 8, first).unwrap(),
            (0x0005_0042, 0x123)
        );
        // Record 0 redirecting to itself.
        values[7].1 = first.to_le_bytes().to_vec();
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert!(resolve_record(&mut read, st, 0xc0, fields, 4, first).is_err());
    }

    #[test]
    fn a_region_entry_is_an_address_or_a_descriptor() {
        let store = 0x10_000;
        let values: Vec<(u64, Vec<u8>)> = vec![
            (store + 0x1b68, 0x20_000u64.to_le_bytes().to_vec()),
            (
                0x20_000 + 3 * 8,
                0x0000_0123_4567_0005u64.to_le_bytes().to_vec(),
            ),
            (store + 0x1a95, vec![0b100]),
        ];
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            region_address(&mut read, store, 0x1b68, (0x1a95, 2), 3).unwrap(),
            0x0123_4567_0000
        );
        let values: Vec<(u64, Vec<u8>)> = vec![
            (store + 0x1b68, 0x20_000u64.to_le_bytes().to_vec()),
            (0x20_000 + 3 * 8, 0x30_003u64.to_le_bytes().to_vec()),
            (store + 0x1a95, vec![0]),
            (
                0x30_000 + 0x18,
                0x0000_0222_0000_0000u64.to_le_bytes().to_vec(),
            ),
        ];
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            region_address(&mut read, store, 0x1b68, (0x1a95, 2), 3).unwrap(),
            0x0222_0000_0000
        );
    }

    #[test]
    fn a_page_key_leads_to_its_store_through_the_table() {
        let manager = 0x10_000;
        let leaf = |key: u32, value: u32| {
            let mut node = vec![0u8; 16];
            node[0] = 1;
            node[3] = 1;
            node.extend_from_slice(&key.to_le_bytes());
            node.extend_from_slice(&value.to_le_bytes());
            node
        };
        let values: Vec<(u64, Vec<u8>)> = vec![
            (manager + 0x1c0, 0x40_000u64.to_le_bytes().to_vec()),
            // Store index 33: row 1, entry 1.
            (0x40_000, leaf(0x2000_1234, 33)),
            (manager + 8, 0x50_000u64.to_le_bytes().to_vec()),
            (0x50_000 + 0x28, 0x60_000u64.to_le_bytes().to_vec()),
        ];
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            store_for_key(&mut read, manager, 0x1c0, 0x2000_1234).unwrap(),
            Some(0x60_000)
        );
        assert_eq!(
            store_for_key(&mut read, manager, 0x1c0, 0x2000_1235).unwrap(),
            None
        );
    }

    #[test]
    fn the_embedded_store_is_the_one_that_points_back() {
        let store = 0x10_000;
        let values: Vec<(u64, Vec<u8>)> = vec![
            // A pointer elsewhere at 0x40's back-pointer slot, the store at 0x50's.
            (store + 0x40 + 0x320, 0x99_000u64.to_le_bytes().to_vec()),
            (store + 0x50 + 0x320, store.to_le_bytes().to_vec()),
        ];
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert_eq!(
            embedded_store(&mut read, store, 0x320).unwrap(),
            store + 0x50
        );
        assert!(embedded_store(&mut read, store + 0x1000, 0x320).is_err());
    }

    #[test]
    fn a_page_decompresses_by_the_stores_algorithm() {
        let (store, st) = (0x10_000u64, 0x10_050u64);
        let original: Vec<u8> = (0..4096u32).map(|i| (i / 64) as u8).collect();
        let decompress = |values: &[(u64, Vec<u8>)], compression, data: &[u8]| {
            let borrowed: Vec<(u64, &[u8])> =
                values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
            let mut page = [0u8; 4096];
            decompress_page(
                &mut memory(&borrowed),
                compression,
                store,
                st,
                data,
                &mut page,
            )
            .map(|()| page.to_vec())
        };
        // 24H2: LZ4 while the store's algorithm count is zero.
        let lz4 = lz4_flex::block::compress(&original);
        let zero = [(store + 0x12c0, 0u32.to_le_bytes().to_vec())];
        assert_eq!(
            decompress(&zero, Compression::Lz4UnlessCount(0x12c0), &lz4).unwrap(),
            original
        );
        let listed = [(store + 0x12c0, 2u32.to_le_bytes().to_vec())];
        assert!(decompress(&listed, Compression::Lz4UnlessCount(0x12c0), &lz4).is_err());
        // Before 24H2: the format field; XPRESS as literals only.
        let mut xpress = Vec::new();
        for group in original.chunks(32) {
            xpress.extend_from_slice(&[0; 4]);
            xpress.extend_from_slice(group);
        }
        xpress.extend_from_slice(&[0; 4]);
        let format = |value: u16| [(st + 0x3e0, value.to_le_bytes().to_vec())];
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
        let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let data = lz4_flex::block::compress(&original);
        let kernel_values: Vec<(u64, Vec<u8>)> = vec![
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
        ];
        let kernel: Vec<(u64, &[u8])> = kernel_values
            .iter()
            .map(|(a, b)| (*a, b.as_slice()))
            .collect();
        let region: Vec<(u64, &[u8])> = vec![(0x0123_0000_0200, data.as_slice())];
        let mut page = [0u8; 4096];
        read_page(
            &mut memory(&kernel),
            &mut memory(&region),
            &layout,
            manager,
            owner,
            key,
            &mut page,
        )
        .unwrap();
        assert_eq!(&page[..], &original[..]);
        // A size word whose low 12 bits are 0 holds the page as it is,
        // whatever the kernel keeps above them.
        let raw: Vec<(u64, Vec<u8>)> = kernel_values
            .iter()
            .map(|(at, value)| match at {
                0x150_014 => (*at, d(0x5000)),
                _ => (*at, value.clone()),
            })
            .collect();
        let raw: Vec<(u64, &[u8])> = raw.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let stored: Vec<(u64, &[u8])> = vec![(0x0123_0000_0200, original.as_slice())];
        page.fill(0xcc);
        read_page(
            &mut memory(&raw),
            &mut memory(&stored),
            &layout,
            manager,
            owner,
            key,
            &mut page,
        )
        .unwrap();
        assert_eq!(&page[..], &original[..]);
        // A store that names another owner is not read.
        let other = read_page(
            &mut memory(&kernel),
            &mut memory(&region),
            &layout,
            manager,
            owner + 8,
            key,
            &mut page,
        );
        assert!(other.is_err());
    }
    #[test]
    fn a_page_record_is_found_through_its_chunk() {
        let st = 0x10_000;
        let key = 0b101 << 8 | 0x03;
        let mut read = memory(&[
            (st + 0x1c8, &8u32.to_le_bytes()),
            (st + 0x1cc, &0xffu32.to_le_bytes()),
            (st + 0x1d0, &12u32.to_le_bytes()),
            (st + 0x1d8, &0x20u32.to_le_bytes()),
            // Slot 2 (0b101's top bit), entry 1 (0b01).
            (st + 0xc0 + 2 * 8, &0x20_000u64.to_le_bytes()),
            (0x20_000 + 16, &0x30_000u64.to_le_bytes()),
        ]);
        let record = page_record(&mut read, st, 0xc0, [0x1c8, 0x1cc, 0x1d0, 0x1d8], key).unwrap();
        assert_eq!(record, 0x30_000 + 0x20 + 12 * 3);
    }

    #[test]
    fn a_key_picks_its_slot_by_its_highest_bit() {
        // With the low 8 bits dropped: 0b1_0110 is slot 4, entry 0b0110.
        assert_eq!(chunk_entry(0b1_0110 << 8 | 0x7f, 8), Some((4, 6 * 16)));
        assert_eq!(chunk_entry(1 << 8, 8), Some((0, 0)));
        assert_eq!(chunk_entry(0xff, 8), None, "no bit above the shift");
    }

    #[test]
    fn a_record_is_past_the_header_by_its_index() {
        assert_eq!(
            record_address(0x1000, 0x1234, 0xff, 12, 0x20),
            0x1000 + 0x20 + 12 * 0x34
        );
    }

    #[test]
    fn a_region_key_splits_into_index_and_offset() {
        assert_eq!(region_location(0x0003_0021, 16, 0xffff), Some((3, 0x210)));
    }
}
