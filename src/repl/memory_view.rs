use owo_colors::OwoColorize;

use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::repl::CommandInvocation;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

pub struct AddressRange {
    pub start: VirtAddr,
    pub end: VirtAddr,
}

/// WinDbg range arguments use `L<count>` (case-insensitive) to distinguish an
/// element count from an end address. Keep ordinary identifiers beginning with
/// `l` available as expressions unless the suffix has count-like syntax.
fn windbg_count_expression(argument: &str) -> Option<&str> {
    let count = argument
        .strip_prefix('L')
        .or_else(|| argument.strip_prefix('l'))?;
    let Some(first) = count.chars().next() else {
        return Some(count);
    };

    if first.is_ascii_digit() || matches!(first, '(' | '@' | '$' | '+' | '-') {
        return Some(count);
    }
    if first.is_ascii_hexdigit() && count.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(count);
    }
    None
}

fn range_length_from_value(
    start: VirtAddr,
    value: VirtAddr,
    explicit_count: bool,
    item_size: u64,
) -> Result<usize> {
    let length = if explicit_count {
        value.0.checked_mul(item_size).ok_or(Error::InvalidRange)?
    } else {
        resolve_length_or_end(start, value).ok_or(Error::InvalidRange)? as u64
    };
    usize::try_from(length).map_err(|_| Error::InvalidRange)
}

pub fn eval_range_length(
    argument: &str,
    debugger: &Target,
    radix: NumberRadix,
    start: VirtAddr,
    item_size: u64,
) -> Result<usize> {
    let (expression, explicit_count) = match windbg_count_expression(argument) {
        Some("") => return Err(Error::InvalidRange),
        Some(count) => (count, true),
        None => (argument, false),
    };
    let value = Expr::eval_with_radix(expression, debugger, radix)?;
    range_length_from_value(start, value, explicit_count, item_size)
}

impl AddressRange {
    pub fn parse(
        invocation: &CommandInvocation<'_>,
        debugger: &Target,
        radix: NumberRadix,
        default_count: u64,
        item_size: u64,
    ) -> Result<Self> {
        let start_arg = invocation.arg(0).ok_or(Error::InvalidRange)?;
        let start = Expr::eval_with_radix(start_arg, debugger, radix)?;

        let length = if let Some(range_arg) = invocation.arg(1) {
            eval_range_length(range_arg, debugger, radix, start, item_size)?
        } else {
            usize::try_from(
                default_count
                    .checked_mul(item_size)
                    .ok_or(Error::InvalidRange)?,
            )
            .map_err(|_| Error::InvalidRange)?
        };
        let end = start
            .0
            .checked_add(u64::try_from(length).map_err(|_| Error::InvalidRange)?)
            .map(VirtAddr)
            .ok_or(Error::InvalidRange)?;

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
    pattern.iter().copied().cycle().take(length).collect()
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
        out!(
            "{}  ",
            ui::addr((start_address + ((i * mode.bytes_per_row) as u64)).0)
        );

        let items_per_row = mode.bytes_per_row / mode.item_size;
        let mut printed = 0;

        for item in chunk.chunks(mode.item_size) {
            match mode.item_format {
                ItemFormat::Bytes => {
                    out!("{:02x} ", item[0]);
                }
                ItemFormat::Dwords => {
                    if item.len() == 4 {
                        let val = u32::from_le_bytes([item[0], item[1], item[2], item[3]]);
                        out!("{:08x} ", val);
                    } else {
                        for byte in item {
                            out!("{:02x}", byte);
                        }
                        out!("   ");
                    }
                }
                ItemFormat::Qwords => {
                    if item.len() == 8 {
                        let val = u64::from_le_bytes([
                            item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7],
                        ]);
                        out!("{:016x} ", val);
                    } else {
                        for byte in item {
                            out!("{:02x}", byte);
                        }
                        out!("   ");
                    }
                }
            }
            printed += 1;
        }

        // pad remaining items if needed
        for _ in printed..items_per_row {
            match mode.item_format {
                ItemFormat::Bytes => out!("   "),
                ItemFormat::Dwords => out!("         "),
                ItemFormat::Qwords => out!("                 "),
            }
        }

        if mode.show_ascii {
            out!(" ");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    out!("{}", *byte as char);
                } else {
                    out!("{}", ".".bright_black());
                }
            }
        }

        outln!();
    }

    outln!();
}

#[cfg(test)]
mod tests {
    use crate::types::VirtAddr;

    use super::{push_string_units, range_length_from_value, windbg_count_expression};

    #[test]
    fn windbg_count_prefix_accepts_numeric_counts_case_insensitively() {
        assert_eq!(windbg_count_expression("L1"), Some("1"));
        assert_eq!(windbg_count_expression("l10"), Some("10"));
        assert_eq!(windbg_count_expression("Lff"), Some("ff"));
        assert_eq!(windbg_count_expression("L(1+2)"), Some("(1+2)"));
        assert_eq!(windbg_count_expression("L"), Some(""));
    }

    #[test]
    fn windbg_count_prefix_does_not_consume_ordinary_identifiers() {
        assert_eq!(windbg_count_expression("limit"), None);
        assert_eq!(windbg_count_expression("LdrpThing"), None);
    }

    #[test]
    fn explicit_count_scales_by_the_commands_element_size() {
        let start = VirtAddr(0xffff_f800_0000_1000);
        assert_eq!(
            range_length_from_value(start, VirtAddr(0x10), true, 4).unwrap(),
            0x40
        );
        assert_eq!(
            range_length_from_value(start, start + 0x40u64, false, 4).unwrap(),
            0x40
        );
        assert!(range_length_from_value(start, VirtAddr(u64::MAX), true, 8).is_err());
    }

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
