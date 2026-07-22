use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::CommandInvocation;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

pub struct AddressRange {
    pub start: VirtAddr,
    pub end: VirtAddr,
}

impl AddressRange {
    pub fn parse(
        invocation: &CommandInvocation<'_>,
        debugger: &Target,
        default_count: u64,
        item_size: u64,
    ) -> Result<Self> {
        let start_arg = invocation.arg(0).ok_or(Error::InvalidRange)?;
        let start = Expr::eval(start_arg, debugger)?;

        let end = if let Some(end_arg) = invocation.arg(1) {
            let end = Expr::eval(end_arg, debugger)?;
            if end.0 < start.0 {
                start + end.0 * item_size
            } else {
                end
            }
        } else {
            start + default_count * item_size
        };

        if end.0 < start.0 {
            return Err(Error::InvalidRange);
        }

        Ok(AddressRange { start, end })
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn len(&self) -> usize {
        (self.end.0 - self.start.0) as usize
    }
}

pub fn parse_byte_pattern(pattern: &str) -> Option<Vec<u8>> {
    if pattern.is_empty() {
        return None;
    }

    if pattern.starts_with("\\x") || pattern.starts_with("\\X") {
        let mut bytes = Vec::new();
        let mut rest = pattern;

        while let Some(stripped) = rest
            .strip_prefix("\\x")
            .or_else(|| rest.strip_prefix("\\X"))
        {
            if stripped.len() < 2 {
                return None;
            }

            let byte = u8::from_str_radix(&stripped[..2], 16).ok()?;
            bytes.push(byte);
            rest = &stripped[2..];
        }

        if rest.is_empty() && !bytes.is_empty() {
            return Some(bytes);
        }

        return None;
    }

    if !pattern.len().is_multiple_of(2) || !pattern.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    hex::decode(pattern).ok()
}

pub fn resolve_length_or_end(start: VirtAddr, end_or_length: VirtAddr) -> Option<usize> {
    let length = if end_or_length.0 < start.0 {
        end_or_length.0
    } else {
        end_or_length.0 - start.0
    };

    usize::try_from(length).ok()
}

pub fn repeat_pattern(pattern: &[u8], length: usize) -> Vec<u8> {
    let mut filled = Vec::with_capacity(length);

    while filled.len() < length {
        let remaining = length - filled.len();
        filled.extend_from_slice(&pattern[..remaining.min(pattern.len())]);
    }

    filled
}

/// Append `char_size`-wide (1 or 2 bytes, little-endian) string units from
/// `buf` to `out` until a NUL unit, `max` total units, or the buffer runs out
/// of whole units. Returns true when the NUL terminator was reached.
pub fn push_string_units(buf: &[u8], char_size: usize, max: usize, out: &mut Vec<u16>) -> bool {
    for unit in buf.chunks_exact(char_size) {
        if out.len() >= max {
            return false;
        }
        let value = match char_size {
            1 => unit[0] as u16,
            _ => u16::from_le_bytes([unit[0], unit[1]]),
        };
        if value == 0 {
            return true;
        }
        out.push(value);
    }
    false
}

pub enum ItemFormat {
    Bytes,
    Dwords,
    Qwords,
}

pub struct MemoryDisplayMode {
    bytes_per_row: usize,
    item_size: usize,
    item_format: ItemFormat,
    show_ascii: bool,
}

impl MemoryDisplayMode {
    pub fn bytes() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 1,
            item_format: ItemFormat::Bytes,
            show_ascii: true,
        }
    }

    pub fn dwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 4,
            item_format: ItemFormat::Dwords,
            show_ascii: false,
        }
    }

    pub fn qwords() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 8,
            item_format: ItemFormat::Qwords,
            show_ascii: false,
        }
    }
}

pub fn display_memory(start_address: VirtAddr, data: &[u8], mode: &MemoryDisplayMode) {
    for (i, chunk) in data.chunks(mode.bytes_per_row).enumerate() {
        print!(
            "{}  ",
            ui::addr((start_address + ((i * mode.bytes_per_row) as u64)).0)
        );

        let items_per_row = mode.bytes_per_row / mode.item_size;
        let mut printed = 0;

        for item in chunk.chunks(mode.item_size) {
            match mode.item_format {
                ItemFormat::Bytes => {
                    print!("{:02x} ", item[0]);
                }
                ItemFormat::Dwords => {
                    if item.len() == 4 {
                        let val = u32::from_le_bytes([item[0], item[1], item[2], item[3]]);
                        print!("{:08x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
                ItemFormat::Qwords => {
                    if item.len() == 8 {
                        let val = u64::from_le_bytes([
                            item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7],
                        ]);
                        print!("{:016x} ", val);
                    } else {
                        for byte in item {
                            print!("{:02x}", byte);
                        }
                        print!("   ");
                    }
                }
            }
            printed += 1;
        }

        // pad remaining items if needed
        for _ in printed..items_per_row {
            match mode.item_format {
                ItemFormat::Bytes => print!("   "),
                ItemFormat::Dwords => print!("         "),
                ItemFormat::Qwords => print!("                 "),
            }
        }

        if mode.show_ascii {
            print!(" ");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!("{}", ".".bright_black());
                }
            }
        }

        println!();
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::push_string_units;

    #[test]
    fn ascii_stops_at_nul_without_pushing_it() {
        let mut out = Vec::new();
        let terminated = push_string_units(b"hi\0junk", 1, 64, &mut out);
        assert!(terminated);
        assert_eq!(out, vec![b'h' as u16, b'i' as u16]);
    }

    #[test]
    fn utf16_decodes_little_endian_units() {
        let mut out = Vec::new();
        let terminated = push_string_units(b"H\0i\0\0\0", 2, 64, &mut out);
        assert!(terminated);
        assert_eq!(out, vec![0x48, 0x69]);
    }

    #[test]
    fn utf16_decodes_non_ascii_unit() {
        let mut out = Vec::new();
        // U+4E2D in little-endian bytes, then a NUL unit.
        let terminated = push_string_units(&[0x2D, 0x4E, 0x00, 0x00], 2, 64, &mut out);
        assert!(terminated);
        assert_eq!(out, vec![0x4E2D]);
    }

    #[test]
    fn max_cap_stops_before_nul() {
        let mut out = Vec::new();
        let terminated = push_string_units(b"abcdef", 1, 3, &mut out);
        assert!(!terminated);
        assert_eq!(out, vec![b'a' as u16, b'b' as u16, b'c' as u16]);

        // Already at the cap: further input pushes nothing.
        let terminated = push_string_units(b"def\0", 1, 3, &mut out);
        assert!(!terminated);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn buffer_exhaustion_ignores_incomplete_unit() {
        let mut out = Vec::new();
        // Two whole UTF-16 units plus a trailing odd byte (incomplete unit).
        let terminated = push_string_units(b"A\0B\0C", 2, 64, &mut out);
        assert!(!terminated);
        assert_eq!(out, vec![0x41, 0x42]);
    }

    #[test]
    fn streaming_accumulates_across_buffers() {
        let mut out = Vec::new();
        // "Hi\0" in UTF-16, split across two page-bounded reads.
        let terminated = push_string_units(b"H\0i\0", 2, 64, &mut out);
        assert!(!terminated);
        let terminated = push_string_units(b"\0\0", 2, 64, &mut out);
        assert!(terminated);
        assert_eq!(out, vec![0x48, 0x69]);
    }
}
