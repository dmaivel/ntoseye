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
