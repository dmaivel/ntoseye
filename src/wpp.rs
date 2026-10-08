//! WPP software tracing messages: the trace message format (TMF) `tracewpp`
//! writes into a driver's private PDB as `S_ANNOTATION` records, and a
//! message rendered from the argument bytes a trace carries.
//!
//! One annotation describes one message:
//!
//! ```text
//! TMF:
//! 4ed73968-00d8-34f3-557f-85fe0ce17799 WdfCore // SRC=Unknown_cxx00 MJ= MN=
//! #typev Unknown_cxx00 11 "%0Handle 0x%10!p!, Type 0x%11!x!" //   LEVEL=TRACE_LEVEL_ERROR FLAGS=TRACINGDEVICE FUNC=FxObjectHandleGetPtrQI
//! {
//! Arg, ItemPtr -- 10
//! Arg, ItemLong -- 11
//! }
//! PUBLIC_TMF:
//! ```
//!
//! `%0` is the trace prefix, `%N!fmt!` argument `N` (from 10) in printf
//! notation, `%!FUNC!` and friends the trailer's keys. Arguments are
//! marshalled back to back in index order, each as its `Item*` type lays it
//! out (tracewpp's `defaultwpp.ini`).

use std::sync::{Arc, OnceLock};

use crate::layout::{EnumDef, le_uint, utf16le_lossy};
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::target::etw::{format_guid, parse_guid};

/// A message's identity: its message GUID's in-memory bytes and its number.
pub type MessageKey = ([u8; 16], u16);

/// One WPP message's trace message format.
#[derive(Debug)]
pub struct TmfMessage {
    /// Message GUID, as its in-memory bytes.
    pub guid: [u8; 16],
    pub number: u16,
    /// The provider (component) name of the header line: `WdfCore`,
    /// `netkvm.sys`.
    pub provider: String,
    /// `SRC=`: the source file.
    pub source_file: Option<String>,
    /// `FUNC=`, or else the procedure whose symbols hold the annotation.
    pub function: Option<String>,
    /// `LEVEL=`: `TRACE_LEVEL_ERROR`, or a number.
    pub level: Option<String>,
    /// `FLAGS=` (`Flags=`, `FLAG=`): the trace flag name.
    pub flags: Option<String>,
    /// The format string, `%0` prefix included.
    pub format: String,
    /// Declared arguments, by ascending index.
    arguments: Vec<TmfArgument>,
}

#[derive(Debug)]
struct TmfArgument {
    index: u16,
    item: Item,
}

/// A TMF argument type (`ItemLong`, `ItemListByte(a,b)`, ...).
#[derive(Debug)]
enum Item {
    /// An integer of `size` bytes: `ItemChar`, `ItemShort`, `ItemLong`,
    /// `ItemLongLong`, ... (their signedness and radix come from the format).
    Integer {
        size: u8,
    },
    /// Pointer-sized integer.
    Ptr,
    /// NUL-terminated ANSI.
    String,
    /// NUL-terminated UTF-16.
    WString,
    /// USHORT byte count, then ANSI bytes (`ANSI_STRING`).
    PString,
    /// USHORT byte count, then UTF-16 bytes (`UNICODE_STRING`).
    PWString,
    Guid,
    NtStatus,
    HResult,
    WinError,
    /// ULONG IPv4 address in network order.
    IpAddr,
    /// USHORT port in network order.
    Port,
    /// `ItemListByte/Short/Long(a,b=5,c)`: value names, `size` bytes.
    List {
        size: u8,
        names: Vec<(u64, String)>,
    },
    /// `ItemEnum(Name)`: a 4-byte C enum the PDB's type stream defines.
    /// Resolved on lookup ([`TmfMessage::resolve_enums`]).
    Enum {
        name: String,
        def: OnceLock<Option<Arc<EnumDef>>>,
    },
    /// A type this module does not decode; formatting the message fails.
    Unsupported(String),
}

impl Item {
    fn parse(text: &str) -> Item {
        let (name, list) = match text.split_once('(') {
            Some((name, rest)) => (name, rest.strip_suffix(')')),
            None => (text, None),
        };
        match (name, list) {
            ("ItemChar" | "ItemUChar", None) => Item::Integer { size: 1 },
            ("ItemShort" | "ItemUShort", None) => Item::Integer { size: 2 },
            ("ItemLong" | "ItemULong" | "ItemULongX", None) => Item::Integer { size: 4 },
            (
                "ItemLongLong" | "ItemULongLong" | "ItemLongLongX" | "ItemLongLongXX"
                | "ItemLongLongO",
                None,
            ) => Item::Integer { size: 8 },
            ("ItemPtr", None) => Item::Ptr,
            ("ItemString", None) => Item::String,
            ("ItemWString", None) => Item::WString,
            ("ItemPString", None) => Item::PString,
            ("ItemPWString", None) => Item::PWString,
            ("ItemGuid", None) => Item::Guid,
            ("ItemNTSTATUS", None) => Item::NtStatus,
            ("ItemHRESULT", None) => Item::HResult,
            ("ItemWINERROR", None) => Item::WinError,
            ("ItemIPAddr", None) => Item::IpAddr,
            ("ItemPort", None) => Item::Port,
            ("ItemListByte", Some(list)) => Item::list(1, list),
            ("ItemListShort", Some(list)) => Item::list(2, list),
            ("ItemListLong", Some(list)) => Item::list(4, list),
            ("ItemEnum", Some(name)) if !name.is_empty() => Item::Enum {
                name: name.to_string(),
                def: OnceLock::new(),
            },
            _ => Item::Unsupported(text.to_string()),
        }
    }

    /// `a,b=0x5,c`: names numbered from 0, or from an explicit value.
    fn list(size: u8, list: &str) -> Item {
        let mut next = 0u64;
        let mut names = Vec::new();
        for entry in list.split(',') {
            let (name, value) = match entry.split_once('=') {
                Some((name, value)) => match parse_number(value.trim()) {
                    Some(value) => (name, value),
                    None => return Item::Unsupported(format!("ItemList({list})")),
                },
                None => (entry, next),
            };
            names.push((value, name.trim().to_string()));
            next = value.wrapping_add(1);
        }
        Item::List { size, names }
    }

    fn name(&self) -> String {
        match self {
            Item::Integer { size } => format!("{}-byte integer", size),
            Item::Ptr => "ItemPtr".into(),
            Item::String => "ItemString".into(),
            Item::WString => "ItemWString".into(),
            Item::PString => "ItemPString".into(),
            Item::PWString => "ItemPWString".into(),
            Item::Guid => "ItemGuid".into(),
            Item::NtStatus => "ItemNTSTATUS".into(),
            Item::HResult => "ItemHRESULT".into(),
            Item::WinError => "ItemWINERROR".into(),
            Item::IpAddr => "ItemIPAddr".into(),
            Item::Port => "ItemPort".into(),
            Item::List { size, .. } => format!("{size}-byte ItemList"),
            Item::Enum { name, .. } => format!("ItemEnum({name})"),
            Item::Unsupported(text) => text.clone(),
        }
    }
}

fn parse_number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The value of `KEY=value` in a `//` trailer, keys matched without case.
fn trailer_value(trailer: &str, keys: &[&str]) -> Option<String> {
    trailer.split_whitespace().find_map(|token| {
        let (key, value) = token.split_once('=')?;
        (keys.iter().any(|k| k.eq_ignore_ascii_case(key)) && !value.is_empty())
            .then(|| value.to_string())
    })
}

/// `<expression>, <Item type> -- <index>`: the type and index. The
/// expression may itself hold commas; the type is the last `, Item...`
/// that runs to the ` -- `.
fn parse_argument(line: &str) -> Option<TmfArgument> {
    let (left, index) = line.rsplit_once(" -- ")?;
    let index = index.trim().parse().ok()?;
    let left = left.trim_end();
    let mut end = left.len();
    let type_start = loop {
        let at = left[..end].rfind(", Item")?;
        let candidate = &left[at + 2..];
        let name_end = candidate.find('(').unwrap_or(candidate.len());
        let name_ok = candidate[..name_end]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if name_ok && (name_end == candidate.len() || candidate.ends_with(')')) {
            break at + 2;
        }
        end = at;
    };
    Some(TmfArgument {
        index,
        item: Item::parse(&left[type_start..]),
    })
}

impl TmfMessage {
    /// Parse one `TMF:` annotation's strings. `enclosing_function` names
    /// the procedure the annotation belongs to, used when the trailer has
    /// no `FUNC=`.
    pub fn parse<S: AsRef<str>>(
        strings: &[S],
        enclosing_function: Option<&str>,
    ) -> Result<TmfMessage, String> {
        let mut lines = strings.iter().map(AsRef::as_ref);
        if lines.next() != Some("TMF:") {
            return Err("not a TMF: annotation".into());
        }
        let header = lines.next().ok_or("no message GUID line")?;
        let (head, header_trailer) = header.split_once("//").unwrap_or((header, ""));
        let (guid_text, provider) = head
            .trim()
            .split_once(' ')
            .ok_or_else(|| format!("no provider in {header:?}"))?;
        let guid = parse_guid(guid_text).ok_or_else(|| format!("bad GUID {guid_text:?}"))?;

        let typev = lines.next().ok_or("no #typev line")?;
        let rest = typev
            .strip_prefix("#typev ")
            .ok_or_else(|| format!("expected #typev, found {typev:?}"))?;
        let mut words = rest.splitn(3, ' ');
        let _source_tag = words.next();
        let number = words
            .next()
            .and_then(|n| n.parse::<u16>().ok())
            .ok_or_else(|| format!("no message number in {typev:?}"))?;
        let quoted = words.next().unwrap_or_default();
        let quoted = quoted
            .strip_prefix('"')
            .ok_or_else(|| format!("no format string in {typev:?}"))?;
        let (format, trailer) = match quoted.rfind("\" //") {
            Some(end) => (&quoted[..end], &quoted[end + 4..]),
            None => (
                quoted
                    .strip_suffix('"')
                    .ok_or_else(|| format!("unterminated format string in {typev:?}"))?,
                "",
            ),
        };

        let mut arguments = Vec::new();
        for line in lines {
            match line.trim() {
                "{" | "}" | "" => continue,
                "PUBLIC_TMF:" => break,
                line => arguments.push(
                    parse_argument(line).ok_or_else(|| format!("bad argument line {line:?}"))?,
                ),
            }
        }
        arguments.sort_by_key(|argument| argument.index);

        Ok(TmfMessage {
            guid,
            number,
            provider: provider.trim().to_string(),
            source_file: trailer_value(header_trailer, &["SRC"]),
            function: trailer_value(trailer, &["FUNC"])
                .or_else(|| enclosing_function.map(str::to_string)),
            level: trailer_value(trailer, &["LEVEL"]),
            flags: trailer_value(trailer, &["FLAGS", "FLAG"]),
            format: format.to_string(),
            arguments,
        })
    }

    pub fn key(&self) -> MessageKey {
        (self.guid, self.number)
    }

    /// Look up each `ItemEnum` type's definition once, by its name.
    pub fn resolve_enums(&self, lookup: impl Fn(&str) -> Option<Arc<EnumDef>>) {
        for argument in &self.arguments {
            if let Item::Enum { name, def } = &argument.item {
                def.get_or_init(|| lookup(name));
            }
        }
    }
}

/// A decoded argument: its integer value (with width) and/or its text.
struct Value {
    number: Option<(u64, u8)>,
    text: Option<String>,
}

fn take<'a>(args: &mut &'a [u8], n: usize, index: u16, item: &Item) -> Result<&'a [u8], String> {
    if args.len() < n {
        return Err(format!(
            "argument {index} ({}) needs {n} bytes, {} left",
            item.name(),
            args.len()
        ));
    }
    let (head, rest) = args.split_at(n);
    *args = rest;
    Ok(head)
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

fn decode(argument: &TmfArgument, args: &mut &[u8], pointer_size: u8) -> Result<Value, String> {
    let index = argument.index;
    let item = &argument.item;
    let number = |value: u64, size: u8| Value {
        number: Some((value, size)),
        text: None,
    };
    let both = |value: u64, size: u8, text: String| Value {
        number: Some((value, size)),
        text: Some(text),
    };
    let text = |text: String| Value {
        number: None,
        text: Some(text),
    };
    Ok(match item {
        Item::Integer { size } => {
            number(le_uint(take(args, usize::from(*size), index, item)?), *size)
        }
        Item::Ptr => number(
            le_uint(take(args, usize::from(pointer_size), index, item)?),
            pointer_size,
        ),
        Item::String => {
            let end = args
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| format!("argument {index} (ItemString) has no NUL"))?;
            let bytes = take(args, end + 1, index, item)?;
            text(latin1(&bytes[..end]))
        }
        Item::WString => {
            let end = args
                .as_chunks::<2>()
                .0
                .iter()
                .position(|unit| *unit == [0, 0])
                .ok_or_else(|| format!("argument {index} (ItemWString) has no NUL"))?;
            let bytes = take(args, end * 2 + 2, index, item)?;
            text(utf16le_lossy(&bytes[..end * 2]))
        }
        Item::PString | Item::PWString => {
            let length = le_uint(take(args, 2, index, item)?) as usize;
            let bytes = take(args, length, index, item)?;
            text(if matches!(item, Item::PString) {
                latin1(bytes)
            } else {
                utf16le_lossy(bytes)
            })
        }
        Item::Guid => {
            let bytes: [u8; 16] = take(args, 16, index, item)?.try_into().unwrap();
            text(format_guid(&bytes))
        }
        Item::NtStatus | Item::HResult | Item::WinError => {
            let value = le_uint(take(args, 4, index, item)?) as u32;
            let name = match item {
                Item::NtStatus => ntstatus_name(value),
                Item::WinError => win32_error_name(value),
                _ => None,
            };
            let rendered = match (item, name) {
                (Item::WinError, Some(name)) => format!("{value}({name})"),
                (Item::WinError, None) => value.to_string(),
                (_, Some(name)) => format!("{value:#x}({name})"),
                (_, None) => format!("{value:#010x}"),
            };
            both(u64::from(value), 4, rendered)
        }
        Item::IpAddr => {
            let bytes = take(args, 4, index, item)?;
            both(
                le_uint(bytes),
                4,
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            )
        }
        Item::Port => {
            let bytes = take(args, 2, index, item)?;
            both(
                le_uint(bytes),
                2,
                u16::from_be_bytes([bytes[0], bytes[1]]).to_string(),
            )
        }
        Item::List { size, names } => {
            let value = le_uint(take(args, usize::from(*size), index, item)?);
            let name = names
                .iter()
                .find(|(v, _)| *v == value)
                .map_or_else(|| value.to_string(), |(_, name)| name.clone());
            both(value, *size, name)
        }
        Item::Enum { def, .. } => {
            let value = le_uint(take(args, 4, index, item)?);
            let signed = i64::from(value as u32 as i32);
            let name = def
                .get()
                .and_then(Option::as_ref)
                .and_then(|def| def.variants.iter().find(|(_, v)| *v == signed))
                .map_or_else(|| signed.to_string(), |(name, _)| name.clone());
            both(value, 4, name)
        }
        Item::Unsupported(name) => {
            return Err(format!("argument {index} has unsupported type {name}"));
        }
    })
}

/// A printf conversion: `[flags][width][.precision][length]type`.
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    precision: Option<usize>,
    conversion: char,
}

fn parse_spec(text: &str) -> Option<Spec> {
    let mut chars = text.chars().peekable();
    let mut spec = Spec {
        left: false,
        plus: false,
        space: false,
        alternate: false,
        zero: false,
        width: 0,
        precision: None,
        conversion: 's',
    };
    while let Some(&c) = chars.peek() {
        match c {
            '-' => spec.left = true,
            '+' => spec.plus = true,
            ' ' => spec.space = true,
            '#' => spec.alternate = true,
            '0' => spec.zero = true,
            _ => break,
        }
        chars.next();
    }
    let digits = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        let mut value = 0usize;
        while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
            value = value.saturating_mul(10).saturating_add(d as usize);
            chars.next();
        }
        value
    };
    spec.width = digits(&mut chars);
    if chars.peek() == Some(&'.') {
        chars.next();
        spec.precision = Some(digits(&mut chars));
    }
    // Length modifiers: the argument's type, not these, sets its width.
    let rest: String = chars.collect();
    let conversion = [
        "I64", "I32", "hh", "ll", "h", "l", "L", "I", "w", "z", "j", "t",
    ]
    .iter()
    .find_map(|prefix| rest.strip_prefix(prefix))
    .unwrap_or(&rest);
    let mut conversion = conversion.chars();
    spec.conversion = conversion.next()?;
    conversion.next().is_none().then_some(spec)
}

fn pad(out: &mut String, body: &str, spec: &Spec) {
    let fill = spec.width.saturating_sub(body.chars().count());
    if spec.left {
        out.push_str(body);
        out.extend(std::iter::repeat_n(' ', fill));
    } else {
        out.extend(std::iter::repeat_n(' ', fill));
        out.push_str(body);
    }
}

fn render_integer(
    out: &mut String,
    value: u64,
    size: u8,
    spec: &Spec,
    pointer_size: u8,
) -> Result<(), String> {
    let bits = u32::from(size) * 8;
    let value = if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    let (sign, prefix, digits) = match spec.conversion {
        'd' | 'i' => {
            let signed = if bits >= 64 {
                value as i64
            } else {
                ((value << (64 - bits)) as i64) >> (64 - bits)
            };
            let sign = if signed < 0 {
                "-"
            } else if spec.plus {
                "+"
            } else if spec.space {
                " "
            } else {
                ""
            };
            (sign, "", signed.unsigned_abs().to_string())
        }
        'u' => ("", "", value.to_string()),
        'x' => (
            "",
            if spec.alternate && value != 0 {
                "0x"
            } else {
                ""
            },
            format!("{value:x}"),
        ),
        'X' => (
            "",
            if spec.alternate && value != 0 {
                "0X"
            } else {
                ""
            },
            format!("{value:X}"),
        ),
        'o' => (
            "",
            if spec.alternate && value != 0 {
                "0"
            } else {
                ""
            },
            format!("{value:o}"),
        ),
        'p' => (
            "",
            if spec.alternate { "0x" } else { "" },
            format!("{value:0width$X}", width = usize::from(pointer_size) * 2),
        ),
        'c' | 'C' => {
            let c = if size == 1 {
                char::from(value as u8)
            } else {
                char::from_u32(value as u32).unwrap_or(char::REPLACEMENT_CHARACTER)
            };
            pad(out, &c.to_string(), spec);
            return Ok(());
        }
        other => return Err(format!("%{other} does not format an integer")),
    };
    let digits = match spec.precision {
        Some(precision) if digits.len() < precision => {
            format!("{}{digits}", "0".repeat(precision - digits.len()))
        }
        _ => digits,
    };
    let length = sign.len() + prefix.len() + digits.len();
    if spec.zero && !spec.left && spec.precision.is_none() && length < spec.width {
        out.push_str(sign);
        out.push_str(prefix);
        out.extend(std::iter::repeat_n('0', spec.width - length));
        out.push_str(&digits);
    } else {
        pad(out, &format!("{sign}{prefix}{digits}"), spec);
    }
    Ok(())
}

/// Render `message` with its argument bytes as WPP marshals them (the bytes a
/// MESSAGE_TRACE_HEADER or an IFR record carries after its header). Err names
/// why the arguments do not fit the message's declared types. Bytes after the
/// last argument are ignored.
pub fn format_message(
    message: &TmfMessage,
    args: &[u8],
    pointer_size: u8,
) -> Result<String, String> {
    if !matches!(pointer_size, 4 | 8) {
        return Err(format!("pointer size {pointer_size}"));
    }
    let mut rest = args;
    let values = message
        .arguments
        .iter()
        .map(|argument| Ok((argument.index, decode(argument, &mut rest, pointer_size)?)))
        .collect::<Result<Vec<(u16, Value)>, String>>()?;

    let format = message.format.as_str();
    let mut out = String::with_capacity(format.len());
    let mut done = 0;
    while let Some(found) = format[done..].find('%') {
        let at = done + found;
        out.push_str(&format[done..at]);
        let after = &format[at + 1..];
        if let Some(special) = after.strip_prefix('!') {
            let name = special
                .split_once('!')
                .map(|(name, _)| name)
                .ok_or_else(|| format!("unterminated %! at {at}"))?;
            let value = match name {
                "FUNC" => message.function.as_deref(),
                "COMPNAME" => Some(message.provider.as_str()),
                "FILE" => message.source_file.as_deref(),
                "LEVEL" => message.level.as_deref(),
                "FLAGS" => message.flags.as_deref(),
                _ => return Err(format!("unknown %!{name}!")),
            }
            .ok_or_else(|| format!("%!{name}! has no value in the TMF"))?;
            out.push_str(value);
            done = at + name.len() + 3;
            continue;
        }
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            match after.chars().next() {
                Some('%') => out.push('%'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                other => {
                    return Err(format!(
                        "unknown insert %{} at {at}",
                        other.map(String::from).unwrap_or_default()
                    ));
                }
            }
            done = at + 2;
            continue;
        }
        let index: u16 = after[..digits]
            .parse()
            .map_err(|_| format!("bad insert %{}", &after[..digits]))?;
        let spec_text = match after[digits..].strip_prefix('!') {
            Some(tail) => {
                let (spec, _) = tail
                    .split_once('!')
                    .ok_or_else(|| format!("unterminated %{index}!"))?;
                done = at + 1 + digits + spec.len() + 2;
                spec
            }
            None => {
                done = at + 1 + digits;
                "s"
            }
        };
        if index == 0 {
            continue;
        }
        let spec =
            parse_spec(spec_text).ok_or_else(|| format!("bad format %{index}!{spec_text}!"))?;
        let (_, value) = values
            .iter()
            .find(|(i, _)| *i == index)
            .ok_or_else(|| format!("%{index} names no declared argument"))?;
        match (spec.conversion, &value.text, value.number) {
            ('s' | 'S', Some(text), _) => {
                let text = match spec.precision {
                    Some(precision) => text.chars().take(precision).collect(),
                    None => text.clone(),
                };
                pad(&mut out, &text, &spec);
            }
            (_, _, Some((number, size))) => {
                render_integer(&mut out, number, size, &spec, pointer_size)
                    .map_err(|e| format!("argument {index}: {e}"))?;
            }
            (conversion, _, None) => {
                return Err(format!("argument {index} is text, format is %{conversion}"));
            }
        }
    }
    out.push_str(&format[done..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TMF annotation's strings, one per line of `text`.
    fn parse(text: &str) -> TmfMessage {
        let strings: Vec<&str> = text.lines().map(str::trim).collect();
        TmfMessage::parse(&strings, Some("Enclosing")).unwrap()
    }

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    // Wdf01000.pdb (26200).
    const OBJECT_TYPE_MISMATCH: &str = r#"TMF:
        4ed73968-00d8-34f3-557f-85fe0ce17799 WdfCore // SRC=Unknown_cxx00 MJ= MN=
        #typev Unknown_cxx00 11 "%0Object Type Mismatch, Handle 0x%10!p!, Type 0x%11!x!, Obj 0x%12!p!, SB 0x%13!x!" //   GLOBALS=Object->GetDriverGlobals() LEVEL=TRACE_LEVEL_ERROR FLAGS=TRACINGDEVICE FUNC=FxObjectHandleGetPtrQI
        {
        Arg, ItemPtr -- 10
        Arg, ItemLong -- 11
        Arg, ItemPtr -- 12
        Arg, ItemLong -- 13
        }
        PUBLIC_TMF:"#;

    fn object_type_mismatch_args() -> Vec<u8> {
        concat(&[
            &0xffff_c50c_6f4a_1230u64.to_le_bytes(),
            &0x1003u32.to_le_bytes(),
            &0xffff_c50c_6f4a_1000u64.to_le_bytes(),
            &0u32.to_le_bytes(),
        ])
    }

    #[test]
    fn parses_tmf_header_typev_trailer_and_arguments() {
        let message = parse(OBJECT_TYPE_MISMATCH);
        assert_eq!(
            message.key(),
            (
                [
                    0x68, 0x39, 0xd7, 0x4e, 0xd8, 0x00, 0xf3, 0x34, 0x55, 0x7f, 0x85, 0xfe, 0x0c,
                    0xe1, 0x77, 0x99
                ],
                11
            )
        );
        assert_eq!(message.provider, "WdfCore");
        assert_eq!(message.source_file.as_deref(), Some("Unknown_cxx00"));
        // FUNC= wins over the enclosing procedure.
        assert_eq!(message.function.as_deref(), Some("FxObjectHandleGetPtrQI"));
        assert_eq!(message.level.as_deref(), Some("TRACE_LEVEL_ERROR"));
        assert_eq!(message.flags.as_deref(), Some("TRACINGDEVICE"));
        let indexes: Vec<u16> = message.arguments.iter().map(|a| a.index).collect();
        assert_eq!(indexes, [10, 11, 12, 13]);

        // A format string holding a newline and a backslash, one annotation string.
        let multiline = TmfMessage::parse(
            &[
                "TMF:",
                "583c7b0b-364c-33d7-41a5-1294b28378e9 WdfCore // SRC=Unknown_cxx00 MJ= MN=",
                "#typev Unknown_cxx00 10 \"%0NULL Required Parameter Passed to a DDI\nFxDriverGlobals\\Wdf 0x%10!p!\" //   LEVEL=TRACE_LEVEL_FATAL FLAGS=TRACINGERROR FUNC=FxVerifierNullBugCheck",
                "{",
                "Arg, ItemPtr -- 10",
                "}",
                "PUBLIC_TMF:",
            ],
            None,
        )
        .unwrap();
        assert_eq!(
            format_message(&multiline, &0x1234u64.to_le_bytes(), 8).unwrap(),
            "NULL Required Parameter Passed to a DDI\nFxDriverGlobals\\Wdf 0x0000000000001234"
        );

        assert!(TmfMessage::parse(&["PUBLIC_TMF:", "FxDriverGlobals"], None).is_err());
    }

    #[test]
    fn formats_pointers_at_the_target_width() {
        let message = parse(OBJECT_TYPE_MISMATCH);
        assert_eq!(
            format_message(&message, &object_type_mismatch_args(), 8).unwrap(),
            "Object Type Mismatch, Handle 0xFFFFC50C6F4A1230, Type 0x1003, \
             Obj 0xFFFFC50C6F4A1000, SB 0x0"
        );
        let x86 = concat(&[
            &0x8a4b_1230u32.to_le_bytes(),
            &7u32.to_le_bytes(),
            &0x8a4b_1000u32.to_le_bytes(),
            &1u32.to_le_bytes(),
        ]);
        assert_eq!(
            format_message(&message, &x86, 4).unwrap(),
            "Object Type Mismatch, Handle 0x8A4B1230, Type 0x7, Obj 0x8A4B1000, SB 0x1"
        );
    }

    #[test]
    fn names_list_and_enum_values() {
        let text = r#"TMF:
            e91d0f2c-4da1-36b3-f22f-a6f5c11dda43 WdfCore // SRC=Unknown_cxx00 MJ= MN=
            #typev Unknown_cxx00 19 "%0WDFDEVICE 0x%10!p! !devobj 0x%11!p! IRP_MJ_POWER, %12!s! IRP 0x%13!p! for %14!s! (S%15!d!)" //   GLOBALS=GetDriverGlobals() LEVEL=TRACE_LEVEL_INFORMATION FLAGS=TRACINGPNP FUNC=FxPkgPnp::Dispatch
            {
            Arg, ItemPtr -- 10
            Arg, ItemPtr -- 11
            Arg, ItemListByte(IRP_MN_WAIT_WAKE,IRP_MN_POWER_SEQUENCE,IRP_MN_SET_POWER,IRP_MN_QUERY_POWER) -- 12
            Arg, ItemPtr -- 13
            Arg, ItemEnum(_SYSTEM_POWER_STATE) -- 14
            Arg, ItemLong -- 15
            }
            PUBLIC_TMF:"#;
        let args = |minor: u8, state: u32| {
            concat(&[
                &0xffff_e001_0000_1000u64.to_le_bytes(),
                &0xffff_e001_0000_2000u64.to_le_bytes(),
                &[minor],
                &0xffff_e001_0000_3000u64.to_le_bytes(),
                &state.to_le_bytes(),
                &4u32.to_le_bytes(),
            ])
        };
        // Unresolved, an enum renders its number.
        let message = parse(text);
        assert_eq!(
            format_message(&message, &args(2, 5), 8).unwrap(),
            "WDFDEVICE 0xFFFFE00100001000 !devobj 0xFFFFE00100002000 IRP_MJ_POWER, \
             IRP_MN_SET_POWER IRP 0xFFFFE00100003000 for 5 (S4)"
        );
        message.resolve_enums(|name| {
            (name == "_SYSTEM_POWER_STATE").then(|| {
                Arc::new(EnumDef {
                    variants: vec![
                        ("PowerSystemWorking".into(), 1),
                        ("PowerSystemHibernate".into(), 5),
                    ],
                    size: Some(4),
                })
            })
        });
        assert_eq!(
            format_message(&message, &args(3, 5), 8).unwrap(),
            "WDFDEVICE 0xFFFFE00100001000 !devobj 0xFFFFE00100002000 IRP_MJ_POWER, \
             IRP_MN_QUERY_POWER IRP 0xFFFFE00100003000 for PowerSystemHibernate (S4)"
        );
        // Values outside the list or enum render as numbers.
        assert_eq!(
            format_message(&message, &args(9, 2), 8).unwrap(),
            "WDFDEVICE 0xFFFFE00100001000 !devobj 0xFFFFE00100002000 IRP_MJ_POWER, \
             9 IRP 0xFFFFE00100003000 for 2 (S4)"
        );

        // Explicit list values restart the numbering.
        let scan = parse(
            r#"TMF:
            15a8d173-19ed-3627-3053-66bb3b198115 core // SRC=Unknown_cxx00 MJ= MN=
            #typev Unknown_cxx00 13 "%0entry %10!p! modified in last scan, mod state  %11!s!,desc state %12!s!" //   GLOBALS=GetDriverGlobals() LEVEL=TRACE_LEVEL_VERBOSE FLAGS=TRACINGPNP FUNC=FxChildList::EndScan
            {
            Arg, ItemPtr -- 10
            Arg, ItemListLong(ModificationUnspecified=0x0,ModificationInsert,ModificationRemove,ModificationRemoveNotify,ModificationClone,ModificationNeedsPnpRemoval) -- 11
            Arg, ItemListLong(DescriptionUnspecified=0x0,DescriptionPresentNeedsInstantiation,DescriptionInstantiatedHasObject,DescriptionReportedMissing,DescriptionNotPresent) -- 12
            }
            PUBLIC_TMF:"#,
        );
        let args = concat(&[
            &0x10u64.to_le_bytes(),
            &2u32.to_le_bytes(),
            &4u32.to_le_bytes(),
        ]);
        assert_eq!(
            format_message(&scan, &args, 8).unwrap(),
            "entry 0000000000000010 modified in last scan, mod state  ModificationRemove,\
             desc state DescriptionNotPresent"
        );
    }

    #[test]
    fn decodes_terminated_and_counted_strings() {
        let unload = parse(
            r#"TMF:
            3c02da23-88b9-3b8e-62c6-8434fde0e0a0 WdfCore // SRC=Unknown_cxx00 MJ= MN=
            #typev Unknown_cxx00 15 "%0Driver Object %10!p!, reg path %11!s! cannot be unloaded, no DriverUnload routine specified" //   GLOBALS=FxDriverGlobals LEVEL=TRACE_LEVEL_INFORMATION FLAGS=TRACINGDRIVER FUNC=FxDriver::Initialize
            {
            Arg, ItemPtr -- 10
            Arg, ItemPWString -- 11
            }
            PUBLIC_TMF:"#,
        );
        let path: Vec<u8> = "\\Registry\\Machine\\vioser"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let args = concat(&[
            &0xffff_9f00_1234_5000u64.to_le_bytes(),
            &(path.len() as u16).to_le_bytes(),
            &path,
        ]);
        assert_eq!(
            format_message(&unload, &args, 8).unwrap(),
            "Driver Object FFFF9F0012345000, reg path \\Registry\\Machine\\vioser cannot be \
             unloaded, no DriverUnload routine specified"
        );
        // The count is in bytes: a shorter one cuts the string.
        let mut short = args.clone();
        short[8] = 18;
        assert_eq!(
            format_message(&unload, &short, 8).unwrap(),
            "Driver Object FFFF9F0012345000, reg path \\Registry cannot be unloaded, no \
             DriverUnload routine specified"
        );

        // virtio-win netkvm.pdb: a wide string, the expression a cast.
        let pnp_id = parse(
            r#"TMF:
            d5d0c4ee-956a-3097-4e88-56ce0557255b netkvm.sys // SRC=ParaNdis_Protocol.cpp MJ= MN=
            #typev ParaNdis_Protocol_cpp76 10 "%0PnpId %10!s!" //   Flags=TRACE_DRIVER LEVEL=0
            {
            (LPCWSTR)buffer, ItemWString -- 10
            }"#,
        );
        assert_eq!(pnp_id.flags.as_deref(), Some("TRACE_DRIVER"));
        assert_eq!(pnp_id.level.as_deref(), Some("0"));
        assert_eq!(
            format_message(&pnp_id, &utf16z("PCI\\VEN_1AF4&DEV_1041"), 8).unwrap(),
            "PnpId PCI\\VEN_1AF4&DEV_1041"
        );

        // virtio-win fwcfg.pdb: an ANSI string cut by its precision.
        let signature = parse(
            r#"TMF:
            daf0e9a0-2b10-3447-1eaf-9aea1b908ccb fwcfg.sys // SRC=fwcfg.c MJ= MN=
            #typev fwcfg_c22 10 "%0Signature is [%10!.4s!]" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=DBG_ALL
            {
            (PCHAR)signature, ItemString -- 10
            }"#,
        );
        assert_eq!(
            format_message(&signature, b"QEMU CFG\0", 8).unwrap(),
            "Signature is [QEMU]"
        );
    }

    #[test]
    fn renders_guids_and_named_statuses() {
        let capability = parse(
            r#"TMF:
            9a6a6e04-7244-37de-5241-9476d4968249 WdfCore // SRC=Unknown_cxx00 MJ= MN=
            #typev Unknown_cxx00 26 "%0Could not retrieve capability %10!s!, %11!s!" //   GLOBALS=GetDriverGlobals() LEVEL=TRACE_LEVEL_ERROR FLAGS=TRACINGIOTARGET FUNC=FxUsbDevice::QueryUsbCapability
            {
            Arg, ItemGuid -- 10
            Arg, ItemNTSTATUS -- 11
            }
            PUBLIC_TMF:"#,
        );
        let guid: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
        let args = |status: u32| concat(&[&guid, &status.to_le_bytes()]);
        assert_eq!(
            format_message(&capability, &args(0xc000_0034), 8).unwrap(),
            "Could not retrieve capability {04030201-0605-0807-090a-0b0c0d0e0f10}, \
             0xc0000034(STATUS_OBJECT_NAME_NOT_FOUND)"
        );
        assert_eq!(
            format_message(&capability, &args(0xc0de_0001), 8).unwrap(),
            "Could not retrieve capability {04030201-0605-0807-090a-0b0c0d0e0f10}, 0xc0de0001"
        );
    }

    #[test]
    fn applies_printf_flags_and_the_enclosing_function() {
        // virtio-win netkvm.pdb: %!FUNC! with no FUNC= in the trailer.
        let rss = parse(
            r#"TMF:
            d74132eb-ba4f-3ca2-c4de-d17a15901870 netkvm.sys // SRC=ParaNdis6_RSS.cpp MJ= MN=
            #typev ParaNdis6_RSS_cpp491 22 "%0[%!FUNC!]RSS Params: flags 0x%10!4.4x!, hash information 0x%11!4.4x!" //   Flags=TRACE_DRIVER LEVEL=0
            {
            Params->Flags, ItemLong -- 10
            Params->HashInformation, ItemLong -- 11
            }"#,
        );
        assert_eq!(rss.function.as_deref(), Some("Enclosing"));
        let args = concat(&[&1u32.to_le_bytes(), &0x12abcu32.to_le_bytes()]);
        assert_eq!(
            format_message(&rss, &args, 8).unwrap(),
            "[Enclosing]RSS Params: flags 0x0001, hash information 0x12abc"
        );

        let io = parse(
            r#"TMF:
            38eda24b-3eb6-3e29-86d9-df5f1362f808 netkvm.sys // SRC=ParaNdis_VirtIO.cpp MJ= MN=
            #typev ParaNdis_VirtIO_cpp126 16 "%0[%!FUNC!]Found IO memory at %10!08I64X!(%11!d!) bar %12!d!" //   Flags=TRACE_DRIVER LEVEL=0
            {
            Start.QuadPart, ItemLongLongXX -- 10
            len, ItemLong -- 11
            bar, ItemLong -- 12
            }"#,
        );
        let args = |start: u64, len: i32| {
            concat(&[
                &start.to_le_bytes(),
                &len.to_le_bytes(),
                &2u32.to_le_bytes(),
            ])
        };
        assert_eq!(
            format_message(&io, &args(0xfe00, -1), 8).unwrap(),
            "[Enclosing]Found IO memory at 0000FE00(-1) bar 2"
        );
        assert_eq!(
            format_message(&io, &args(0x8_0000_1000, 4096), 8).unwrap(),
            "[Enclosing]Found IO memory at 800001000(4096) bar 2"
        );

        // The argument expression holds commas and quotes.
        let checksum = parse(
            r#"TMF:
            d5d0c4ee-956a-3097-4e88-56ce0557255b netkvm.sys // SRC=ParaNdis_Protocol.cpp MJ= MN=
            #typev ParaNdis_Protocol_cpp367 20 "%0Checksum6 TX: ipx %10!d!, tcp %11!d!%12!c!, udp %13!d!" //   Flags=TRACE_DRIVER LEVEL=0
            {
            cso.IPv6Transmit.IpExtensionHeadersSupported, ItemLong -- 10
            cso.IPv6Transmit.TcpChecksum, ItemLong -- 11
            cso.IPv6Transmit.TcpOptionsSupported ? '+' : ' ', ItemChar -- 12
            cso.IPv6Transmit.UdpChecksum, ItemLong -- 13
            }"#,
        );
        let args = concat(&[
            &1u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            b"+",
            &1u32.to_le_bytes(),
        ]);
        assert_eq!(
            format_message(&checksum, &args, 8).unwrap(),
            "Checksum6 TX: ipx 1, tcp 0+, udp 1"
        );
    }

    #[test]
    fn refuses_arguments_that_do_not_fit() {
        let message = parse(OBJECT_TYPE_MISMATCH);
        let args = object_type_mismatch_args();
        // One byte short of the last ItemLong.
        assert!(format_message(&message, &args[..args.len() - 1], 8).is_err());
        // Trailing bytes (an IFR record's padding) are not arguments.
        let mut padded = args.clone();
        padded.extend([0, 0, 0]);
        assert_eq!(
            format_message(&message, &padded, 8),
            format_message(&message, &args, 8)
        );

        let string = parse(
            r#"TMF:
            56f98605-4376-35b7-7a26-05fb1d03109f balloon.sys // SRC=balloon.c MJ= MN=
            #typev balloon_c206 22 "%0<-- %10!s!" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=DBG_HW_ACCESS
            {
            __FUNCTION__, ItemString -- 10
            }"#,
        );
        assert_eq!(
            format_message(&string, b"BalloonFill\0", 8).unwrap(),
            "<-- BalloonFill"
        );
        // No NUL: the string ran past the payload.
        assert!(format_message(&string, b"BalloonFill", 8).is_err());

        // A counted string longer than the bytes left.
        let counted = parse(
            r#"TMF:
            9a6a6e04-7244-37de-5241-9476d4968249 WdfCore // SRC=Unknown_cxx00 MJ= MN=
            #typev Unknown_cxx00 25 "%0Error opening %10!s! sub key under WUDF %11!s!" //   GLOBALS=DriverGlobals LEVEL=TRACE_LEVEL_ERROR FLAGS=TRACINGPNP FUNC=FxCompanionLibrary::IsCompanionRequiredForDevice
            {
            Arg, ItemPWString -- 10
            Arg, ItemNTSTATUS -- 11
            }
            PUBLIC_TMF:"#,
        );
        assert!(format_message(&counted, &[8, 0, b'a', 0, b'b', 0], 8).is_err());

        // A type the formatter does not decode keeps the message, but it
        // does not format.
        let set = parse(
            r#"TMF:
            56f98605-4376-35b7-7a26-05fb1d03109f balloon.sys // SRC=balloon.c MJ= MN=
            #typev balloon_c99 23 "%0state %10!s!" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=DBG_HW_ACCESS
            {
            state, ItemSetLong(A,B,C) -- 10
            }"#,
        );
        assert_eq!(set.number, 23);
        assert!(format_message(&set, &1u32.to_le_bytes(), 8).is_err());

        // %s asks for text an integer does not have.
        let mismatch = parse(
            r#"TMF:
            56f98605-4376-35b7-7a26-05fb1d03109f balloon.sys // SRC=balloon.c MJ= MN=
            #typev balloon_c99 24 "%0count %10!s!" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=DBG_HW_ACCESS
            {
            count, ItemLong -- 10
            }"#,
        );
        assert!(format_message(&mismatch, &1u32.to_le_bytes(), 8).is_err());
    }
}
