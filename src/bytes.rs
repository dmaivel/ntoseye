//! Little-endian integer access and C-string termination in byte buffers.
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
}
