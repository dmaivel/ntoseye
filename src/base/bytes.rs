//! Little-endian integer access, C-string termination and UTF-16 text in
//! byte buffers.
//!
//! `get_*` return `None` when the field runs past the buffer and suit
//! offsets taken from untrusted data. `read_*` and `write_*` index directly
//! and panic when out of bounds: they serve fixed layouts (KD packets, dump
//! headers, register buffers) whose length the caller validated or sized up
//! front, where an out-of-range field is a layout bug rather than bad input.

fn get<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

#[track_caller]
fn read<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("range spans N bytes")
}

pub fn get_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    get(bytes, offset).map(u16::from_le_bytes)
}

pub fn get_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    get(bytes, offset).map(u32::from_le_bytes)
}

pub fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    get(bytes, offset).map(u64::from_le_bytes)
}

#[track_caller]
pub fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read(bytes, offset))
}

#[track_caller]
pub fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read(bytes, offset))
}

#[track_caller]
pub fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(read(bytes, offset))
}

#[track_caller]
pub fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[track_caller]
pub fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[track_caller]
pub fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// The bytes before the first NUL; all of `bytes` when it holds none.
pub fn before_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// [`before_nul`] decoded as UTF-8, replacing invalid sequences.
pub fn c_string_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(before_nul(bytes)).into_owned()
}

/// Decode little-endian UTF-16 (`WCHAR` text), replacing unpaired surrogates.
/// A trailing odd byte is not a code unit and is dropped.
pub fn utf16le_lossy(bytes: &[u8]) -> String {
    decode_utf16le(utf16le_units(bytes))
}

/// [`utf16le_lossy`] up to the first NUL unit, for a `WCHAR` buffer that
/// holds a terminated string.
pub fn utf16le_nul_terminated(bytes: &[u8]) -> String {
    decode_utf16le(utf16le_units(bytes).take_while(|unit| *unit != 0))
}

fn utf16le_units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
}

fn decode_utf16le(units: impl Iterator<Item = u16>) -> String {
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string ends at the first NUL, runs to the end of the buffer
    /// without one, and is empty when the buffer starts with one.
    #[test]
    fn before_nul_stops_at_the_first_nul() {
        assert_eq!(before_nul(b"ab\0c\0"), b"ab");
        assert_eq!(before_nul(b"abc"), b"abc");
        assert_eq!(before_nul(b"\0abc"), b"");
        assert_eq!(before_nul(b""), b"");
        assert_eq!(c_string_lossy(b"a\xffb\0c"), "a\u{fffd}b");
    }

    #[test]
    fn wide_text_pairs_surrogates_and_stops_at_nul_only_when_terminated() {
        // "a", U+1F600 as a surrogate pair, NUL, "b".
        let bytes: Vec<u8> = [0x61u16, 0xd83d, 0xde00, 0, 0x62]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16le_nul_terminated(&bytes), "a\u{1f600}");
        assert_eq!(utf16le_lossy(&bytes), "a\u{1f600}\0b");
    }
}
