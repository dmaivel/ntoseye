use owo_colors::OwoColorize;

use crate::disasm::DisasmRow;
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

    if first.is_ascii_digit() || matches!(first, '(' | '@' | '$' | '+' | '-' | '?') {
        return Some(count);
    }
    if first.is_ascii_hexdigit() && count.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(count);
    }
    None
}

/// The second half of a WinDbg range, after its start address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RangeEnd {
    /// `L<count>` (or `L?<count>`) elements from the start.
    Count(u64),
    /// `L-<count>` elements ending just before the start.
    CountBack(u64),
    /// A value: an end address, or a length in bytes when it is below the
    /// start, which no end address can be.
    Value(u64),
}

/// Where `end` leaves a range starting at `start` of `item_size`-byte
/// elements. An end address is inclusive: the range runs through the element
/// containing it.
fn resolve_range(start: VirtAddr, end: RangeEnd, item_size: u64) -> Result<AddressRange> {
    let bytes = |count: u64| count.checked_mul(item_size).ok_or(Error::InvalidRange);
    let (start, length) = match end {
        RangeEnd::Count(count) => (start, bytes(count)?),
        RangeEnd::CountBack(count) => {
            let length = bytes(count)?;
            (
                VirtAddr(start.0.checked_sub(length).ok_or(Error::InvalidRange)?),
                length,
            )
        }
        RangeEnd::Value(length) if length < start.0 => (start, length),
        RangeEnd::Value(end) => (start, bytes((end - start.0) / item_size + 1)?),
    };
    let end = start
        .0
        .checked_add(length)
        .map(VirtAddr)
        .ok_or(Error::InvalidRange)?;
    Ok(AddressRange { start, end })
}

/// Evaluate `argument`, the end of a range starting at `start`: `L<count>`,
/// `L?<count>`, or `L-<count>` elements of `item_size` bytes, an inclusive
/// end address, or a byte length.
pub fn eval_range(
    argument: &str,
    debugger: &Target,
    radix: NumberRadix,
    start: VirtAddr,
    item_size: u64,
) -> Result<AddressRange> {
    let eval = |text: &str| Expr::eval_with_radix(text, debugger, radix).map(|value| value.0);
    let end = match windbg_count_expression(argument) {
        Some("") => return Err(Error::InvalidRange),
        // WinDbg's `L?` lifts its own range limit; the limits here are fixed.
        Some(count) => {
            let count = count.strip_prefix('?').unwrap_or(count);
            match count.strip_prefix('-') {
                Some(back) => RangeEnd::CountBack(eval(back)?),
                None => RangeEnd::Count(eval(count)?),
            }
        }
        None => RangeEnd::Value(eval(argument)?),
    };
    resolve_range(start, end, item_size)
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
        match invocation.arg(1) {
            Some(range_arg) => eval_range(range_arg, debugger, radix, start, item_size),
            None => resolve_range(start, RangeEnd::Count(default_count), item_size),
        }
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

pub fn repeat_pattern(pattern: &[u8], length: usize) -> Vec<u8> {
    pattern.iter().copied().cycle().take(length).collect()
}

/// What a `#` without a pattern or address continues with.
#[derive(Clone, Debug, Default)]
pub struct DisasmSearch {
    pub pattern: Option<String>,
    /// The instruction after the last match, or after the last one searched.
    pub next: Option<VirtAddr>,
}

/// Where a `u` given no address continues: after the last instruction the
/// previous `u` listed, while the context it listed them in holds. After a
/// stop or step, or in another frame, thread or process, the next `u` starts
/// at the scope's instruction pointer instead, as WinDbg's does after a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisasmCursor {
    next: VirtAddr,
    context: DisasmContext,
}

/// What a [`DisasmCursor`] belongs to: the halt (see
/// [`crate::phys::PhysMem::halt_epoch`]), the scope's instruction pointer,
/// and the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DisasmContext {
    halt_epoch: Option<u64>,
    ip: Option<u64>,
    dtb: u64,
}

impl DisasmContext {
    fn of(target: &Target) -> Self {
        Self {
            halt_epoch: target.phys.halt_epoch(),
            ip: target.builtin_variable_value("ip"),
            dtb: target.current_dtb(),
        }
    }
}

impl DisasmCursor {
    /// The cursor past `rows`, listed in `target`'s current context.
    pub fn after(target: &Target, rows: &[DisasmRow]) -> Option<Self> {
        let last = rows.last()?;
        Some(Self {
            next: VirtAddr(last.ip.wrapping_add(last.length as u64)),
            context: DisasmContext::of(target),
        })
    }

    /// Where a `u` given no address starts: at `cursor` while its context
    /// holds, else at the scope's instruction pointer, which a running target
    /// or one without registers does not have.
    pub fn start(cursor: Option<&Self>, target: &Target) -> Result<VirtAddr> {
        if let Some(cursor) = cursor.filter(|cursor| cursor.context == DisasmContext::of(target)) {
            return Ok(cursor.next);
        }
        target
            .builtin_variable_value("ip")
            .map(VirtAddr)
            .ok_or_else(|| {
                Error::DebugInfo("no address to disassemble: give one, or halt the target".into())
            })
    }
}

pub enum ItemFormat {
    Bytes,
    Words,
    Dwords,
    Qwords,
    Binary,
    Floats,
    Doubles,
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

    /// `df`: four single-precision values a row, as WinDbg lays them out.
    pub fn floats() -> Self {
        Self {
            bytes_per_row: 16,
            item_size: 4,
            item_format: ItemFormat::Floats,
            show_ascii: false,
        }
    }

    /// `dD`: three double-precision values a row, as WinDbg lays them out.
    pub fn doubles() -> Self {
        Self {
            bytes_per_row: 24,
            item_size: 8,
            item_format: ItemFormat::Doubles,
            show_ascii: false,
        }
    }
}

const FLOAT_WIDTH: usize = 15;
const DOUBLE_WIDTH: usize = 23;

/// A floating-point value in decimal when its magnitude reads well that way
/// (1e-4 up to 1e15, or zero), else in scientific notation.
pub fn format_float<T>(value: T) -> String
where
    T: Copy + std::fmt::Display + std::fmt::LowerExp + Into<f64>,
{
    let magnitude = value.into().abs();
    if magnitude == 0.0 || (1e-4..1e15).contains(&magnitude) {
        value.to_string()
    } else {
        format!("{value:e}")
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
                    ItemFormat::Floats => out!("{:>FLOAT_WIDTH$} ", "?"),
                    ItemFormat::Doubles => out!("{:>DOUBLE_WIDTH$} ", "?"),
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
                ItemFormat::Floats => match <[u8; 4]>::try_from(item) {
                    Ok(bytes) => out!("{:>FLOAT_WIDTH$} ", format_float(f32::from_le_bytes(bytes))),
                    Err(_) => out!("{:>FLOAT_WIDTH$} ", "?"),
                },
                ItemFormat::Doubles => match <[u8; 8]>::try_from(item) {
                    Ok(bytes) => out!(
                        "{:>DOUBLE_WIDTH$} ",
                        format_float(f64::from_le_bytes(bytes))
                    ),
                    Err(_) => out!("{:>DOUBLE_WIDTH$} ", "?"),
                },
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
                ItemFormat::Floats => out!("{:FLOAT_WIDTH$} ", ""),
                ItemFormat::Doubles => out!("{:DOUBLE_WIDTH$} ", ""),
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

    use super::{RangeEnd, SearchKind, resolve_range, windbg_count_expression};

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

    /// WinDbg's range forms: `L<count>` counts elements, `L-<count>` counts
    /// them back from the start, and an end address is inclusive, through
    /// the element containing it (`0x1000 0x1007` is 8 bytes, 2 dwords, as
    /// is `0x1000 0x1004`). A value below the start is a byte length.
    #[test]
    fn ranges_follow_windbg_forms() {
        let span = |end: RangeEnd, size: u64| {
            let range = resolve_range(VirtAddr(0x1000), end, size).unwrap();
            (range.start.0, range.len())
        };
        assert_eq!(span(RangeEnd::Count(0x10), 4), (0x1000, 0x40));
        assert_eq!(span(RangeEnd::CountBack(0x20), 1), (0xfe0, 0x20));
        assert_eq!(span(RangeEnd::Value(0x1007), 1), (0x1000, 8));
        assert_eq!(span(RangeEnd::Value(0x1007), 4), (0x1000, 8));
        assert_eq!(span(RangeEnd::Value(0x1004), 4), (0x1000, 8));
        assert_eq!(span(RangeEnd::Value(0x1000), 8), (0x1000, 8));
        assert_eq!(span(RangeEnd::Value(0x20), 1), (0x1000, 0x20));
        assert!(resolve_range(VirtAddr(0x1000), RangeEnd::Count(u64::MAX), 8).is_err());
        assert!(resolve_range(VirtAddr(0x10), RangeEnd::CountBack(0x20), 1).is_err());
    }
}
