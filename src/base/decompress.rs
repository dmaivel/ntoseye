//! Decompressors for the formats Windows compresses pages with: LZ4 (the
//! page format from Windows 11 24H2) and plain LZ77 "XPRESS"
//! (`COMPRESSION_FORMAT_XPRESS`, before 24H2), as [MS-XCA] section 2.4
//! defines it.

use crate::base::error::{Error, Result};

/// Decompress an LZ4 block into `out`, which must come out exactly full.
pub fn lz4(input: &[u8], out: &mut [u8]) -> Result<()> {
    let written = lz4_flex::block::decompress_into(input, out)
        .map_err(|error| Error::DebugInfo(format!("LZ4: {error}")))?;
    exact(written, out.len())
}

/// Decompress plain LZ77 (XPRESS) data into `out`, which must come out
/// exactly full.
pub fn xpress(input: &[u8], out: &mut [u8]) -> Result<()> {
    let bad = |what: &str| Error::DebugInfo(format!("XPRESS: {what}"));
    let mut written = 0usize;
    let mut position = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    // The position of the nibble shared by two length encodings, if any.
    let mut last_length_half: Option<usize> = None;
    let byte = |position: &mut usize| -> Result<u8> {
        let value = *input.get(*position).ok_or_else(|| bad("truncated"))?;
        *position += 1;
        Ok(value)
    };
    let word = |position: &mut usize| -> Result<u16> {
        let bytes = input
            .get(*position..*position + 2)
            .ok_or_else(|| bad("truncated"))?;
        *position += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let dword = |position: &mut usize| -> Result<u32> {
        let bytes = input
            .get(*position..*position + 4)
            .ok_or_else(|| bad("truncated"))?;
        *position += 4;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    loop {
        if flag_count == 0 {
            flags = dword(&mut position)?;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1 << flag_count) == 0 {
            if written == out.len() {
                break;
            }
            out[written] = byte(&mut position)?;
            written += 1;
            continue;
        }
        if position == input.len() {
            break;
        }
        let match_bytes = word(&mut position)?;
        let offset = usize::from(match_bytes >> 3) + 1;
        let mut length = usize::from(match_bytes & 7);
        if length == 7 {
            match last_length_half.take() {
                None => {
                    last_length_half = Some(position);
                    length = usize::from(byte(&mut position)? & 0xf);
                }
                Some(at) => length = usize::from(input[at] >> 4),
            }
            if length == 15 {
                length = usize::from(byte(&mut position)?);
                if length == 255 {
                    length = usize::from(word(&mut position)?);
                    if length == 0 {
                        length = dword(&mut position)? as usize;
                    }
                    length = length
                        .checked_sub(15 + 7)
                        .ok_or_else(|| bad("bad length"))?;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        let start = written
            .checked_sub(offset)
            .ok_or_else(|| bad("bad offset"))?;
        if written + length > out.len() {
            return Err(bad("output overrun"));
        }
        for index in 0..length {
            out[written + index] = out[start + index];
        }
        written += length;
    }
    exact(written, out.len())
}

fn exact(written: usize, wanted: usize) -> Result<()> {
    if written == wanted {
        Ok(())
    } else {
        Err(Error::DebugInfo(format!(
            "decompressed {written:#x} bytes, expected {wanted:#x}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page must decompress to exactly a page; less is refused, not
    /// padded.
    #[test]
    fn lz4_data_must_fill_the_page() {
        let page: Vec<u8> = (0..4096u32).map(|i| (i % 7) as u8).collect();
        let mut out = [0u8; 4096];
        lz4(&lz4_flex::block::compress(&page), &mut out).unwrap();
        assert_eq!(&out[..], &page[..]);
        let short = lz4_flex::block::compress(&page[..4000]);
        assert!(lz4(&short, &mut out).is_err());
    }

    #[test]
    fn xpress_decodes_the_spec_examples() {
        // [MS-XCA] 3.1: "abcdefghijklmnopqrstuvwxyz".
        let alphabet = [
            0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7a,
        ];
        let mut out = [0u8; 26];
        xpress(&alphabet, &mut out).unwrap();
        assert_eq!(&out, b"abcdefghijklmnopqrstuvwxyz");
        // [MS-XCA] 3.2: "abc" repeated to 300 bytes.
        let repeated = [
            0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
        ];
        let mut out = [0u8; 300];
        xpress(&repeated, &mut out).unwrap();
        assert!(out.chunks(3).all(|c| c == b"abc"));
    }

    #[test]
    fn xpress_refuses_a_match_before_the_start() {
        let mut out = [0u8; 8];
        assert!(xpress(&[0x80, 0, 0, 0x80, 0x08, 0x00], &mut out).is_err());
    }
}
