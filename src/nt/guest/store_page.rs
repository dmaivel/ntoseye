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

#[cfg(test)]
mod tests {
    use super::*;

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
