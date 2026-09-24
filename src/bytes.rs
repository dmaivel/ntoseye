//! Little-endian integer access into byte buffers.
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
