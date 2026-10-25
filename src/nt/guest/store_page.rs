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

/// The key and compressed size in the page record that region key `key`
/// leads to, following records that redirect to another key (key
/// `0xffffffff`, the next key at +4).
pub fn resolve_record(
    read: &mut impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    st: u64,
    chunk_array: u32,
    fields: [u32; 4],
    key: u32,
) -> crate::base::error::Result<(u32, u16)> {
    let mut key = key;
    for _ in 0..=MAX_REDIRECTS {
        let record = page_record(read, st, chunk_array, fields, key)?;
        let record_key = read_u32(read, record)?;
        let next = read_u32(read, record + 4)?;
        if record_key != u32::MAX {
            return Ok((record_key, next as u16));
        }
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
            resolve_record(&mut read, st, 0xc0, fields, first).unwrap(),
            (0x0005_0042, 0x123)
        );
        // Record 0 redirecting to itself.
        values[7].1 = first.to_le_bytes().to_vec();
        let borrowed: Vec<(u64, &[u8])> = values.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        let mut read = memory(&borrowed);
        assert!(resolve_record(&mut read, st, 0xc0, fields, first).is_err());
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
