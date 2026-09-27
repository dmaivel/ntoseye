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
pub fn windbg_count_expression(argument: &str) -> Option<&str> {
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

/// What `s` searches for, by its WinDbg flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchKind {
    Bytes,
    Words,
    Dwords,
    Qwords,
    Ascii,
    Unicode,
}

impl SearchKind {
    pub fn from_flag(flag: &str) -> Option<Self> {
        Some(match flag {
            "-b" => Self::Bytes,
            "-w" => Self::Words,
            "-d" => Self::Dwords,
            "-q" => Self::Qwords,
            "-a" => Self::Ascii,
            "-u" => Self::Unicode,
            _ => return None,
        })
    }

    /// Bytes per element, the unit of an `L<count>` range.
    pub fn element_size(self) -> u64 {
        match self {
            Self::Bytes | Self::Ascii => 1,
            Self::Words | Self::Unicode => 2,
            Self::Dwords => 4,
            Self::Qwords => 8,
        }
    }

    /// The bytes to search for. Bytes are hex strings (`4d5a`, `\x4d\x5a`)
    /// or values; values are evaluated with `eval` and stored little-endian
    /// in the element's width; a string's arguments are one string joined
    /// by spaces.
    pub fn pattern(self, args: &[&str], eval: impl Fn(&str) -> Result<u64>) -> Result<Vec<u8>> {
        let width = self.element_size() as usize;
        let mut pattern = Vec::new();
        match self {
            Self::Ascii => pattern.extend(args.join(" ").bytes()),
            Self::Unicode => {
                for unit in args.join(" ").encode_utf16() {
                    pattern.extend(unit.to_le_bytes());
                }
            }
            Self::Bytes | Self::Words | Self::Dwords | Self::Qwords => {
                for arg in args {
                    if self == Self::Bytes
                        && let Some(bytes) = parse_byte_pattern(arg)
                    {
                        pattern.extend(bytes);
                        continue;
                    }
                    let value = eval(arg)?;
                    if width < 8 && value >> (width * 8) != 0 {
                        return Err(Error::InvalidArgument(format!(
                            "{arg} ({value:#x}) does not fit in {width} byte{}",
                            if width == 1 { "" } else { "s" }
                        )));
                    }
                    pattern.extend(&value.to_le_bytes()[..width]);
                }
            }
        }
        if pattern.is_empty() {
            return Err(Error::InvalidArgument("empty search pattern".into()));
        }
        Ok(pattern)
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

pub enum ItemFormat {
    Bytes,
    Words,
    Dwords,
    Qwords,
    Binary,
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

    pub fn words() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 2,
            item_format: ItemFormat::Words,
            show_ascii: false,
        }
    }

    pub fn words_ascii() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 2,
            item_format: ItemFormat::Words,
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

    pub fn dwords_ascii() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 4,
            item_format: ItemFormat::Dwords,
            show_ascii: true,
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

    pub fn binary() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 1,
            item_format: ItemFormat::Binary,
            show_ascii: false,
        }
    }
}

/// Render a memory listing while preserving rows that contain unreadable
/// bytes. `validity`, when supplied, has one entry per byte in `data`; an
/// invalid item is shown as question marks and the ASCII column uses `?` for
/// each unavailable byte.
pub fn display_memory_with_validity(
    start_address: VirtAddr,
    data: &[u8],
    validity: Option<&[bool]>,
    mode: &MemoryDisplayMode,
) {
    for (i, chunk) in data.chunks(mode.bytes_per_row).enumerate() {
        out!(
            "{}  ",
            ui::addr((start_address + ((i * mode.bytes_per_row) as u64)).0)
        );

        let items_per_row = mode.bytes_per_row / mode.item_size;
        let mut printed = 0;

        for item in chunk.chunks(mode.item_size) {
            let item_start = i * mode.bytes_per_row + printed * mode.item_size;
            let readable = validity.is_none_or(|valid| {
                item.iter()
                    .enumerate()
                    .all(|(offset, _)| valid.get(item_start + offset).copied().unwrap_or(false))
            });
            if !readable {
                match mode.item_format {
                    ItemFormat::Bytes => out!("?? "),
                    ItemFormat::Words => out!("???? "),
                    ItemFormat::Dwords => out!("???????? "),
                    ItemFormat::Qwords => out!("???????????????? "),
                    ItemFormat::Binary => out!("???????? ?? "),
                }
                printed += 1;
                continue;
            }

            match mode.item_format {
                ItemFormat::Bytes => out!("{:02x} ", item[0]),
                ItemFormat::Words => {
                    if item.len() == 2 {
                        let val = u16::from_le_bytes([item[0], item[1]]);
                        out!("{:04x} ", val);
                    } else {
                        for byte in item {
                            out!("{:02x}", byte);
                        }
                        out!("  ");
                    }
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
                ItemFormat::Binary => {
                    out!("{:08b}", item[0]);
                    out!(" {:02x}", item[0]);
                    out!(" ");
                }
            }
            printed += 1;
        }

        for _ in printed..items_per_row {
            match mode.item_format {
                ItemFormat::Bytes => out!("   "),
                ItemFormat::Words => out!("     "),
                ItemFormat::Dwords => out!("         "),
                ItemFormat::Qwords => out!("                 "),
                ItemFormat::Binary => out!("            "),
            }
        }

        if mode.show_ascii {
            out!(" ");
            for (offset, byte) in chunk.iter().enumerate() {
                let readable = validity.is_none_or(|valid| {
                    valid
                        .get(i * mode.bytes_per_row + offset)
                        .copied()
                        .unwrap_or(false)
                });
                if !readable {
                    out!("?");
                } else if byte.is_ascii_graphic() || *byte == b' ' {
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

    use super::{SearchKind, range_length_from_value, windbg_count_expression};

    /// A value searched as a word or dword is stored little-endian in that
    /// width, and one that does not fit is refused rather than truncated;
    /// bytes take hex strings and values alike, and a string's words are
    /// one string.
    #[test]
    fn search_patterns_encode_each_kind_in_its_width() {
        let eval = |text: &str| {
            u64::from_str_radix(text.trim_start_matches("0x"), 16)
                .map_err(|_| crate::error::Error::InvalidArgument(text.into()))
        };
        let pattern = |kind: SearchKind, args: &[&str]| kind.pattern(args, eval);

        assert_eq!(
            pattern(SearchKind::Bytes, &["4d", "5a90", "\\x00"]).unwrap(),
            [0x4d, 0x5a, 0x90, 0]
        );
        assert_eq!(
            pattern(SearchKind::Words, &["5a4d", "1"]).unwrap(),
            [0x4d, 0x5a, 1, 0]
        );
        assert_eq!(
            pattern(SearchKind::Dwords, &["c0000005"]).unwrap(),
            [5, 0, 0, 0xc0]
        );
        assert!(pattern(SearchKind::Words, &["10000"]).is_err());
        assert!(pattern(SearchKind::Bytes, &["100"]).is_err());
        assert_eq!(
            pattern(SearchKind::Unicode, &["a", "b"]).unwrap(),
            [b'a', 0, b' ', 0, b'b', 0]
        );
    }

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
}
