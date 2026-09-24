//! PDB type layouts: the parsed type model, name queries over it, and
//! cursors that read typed structs out of guest memory.

use std::collections::HashMap;
use std::fmt;

use crate::error::{Error, Result};

mod cursor;
pub use cursor::{StructRef, Types};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParsedType {
    Primitive(String),
    Struct(String),
    Union(String),
    Enum(String),
    Pointer(Box<ParsedType>),
    Array(Box<ParsedType>, u32),
    Bitfield {
        underlying: Box<ParsedType>,
        pos: u8,
        len: u8,
    },
    Function(Box<ParsedType>, Vec<ParsedType>),
    Unknown,
}

impl ParsedType {
    /// The element count when this is a fixed array of single-byte char-like
    /// primitives, i.e. an inline C string buffer such as
    /// `_EPROCESS.ImageFileName` (`UCHAR[15]`). `None` for anything else. Lets a
    /// host auto-decode such fields to text instead of handing back raw bytes.
    pub fn c_string_len(&self) -> Option<u32> {
        match self {
            ParsedType::Array(inner, count) => match inner.as_ref() {
                ParsedType::Primitive(name) if matches!(name.as_str(), "CHAR" | "UCHAR") => {
                    Some(*count)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for ParsedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn signature(f: &mut fmt::Formatter<'_>, args: &[ParsedType]) -> fmt::Result {
            f.write_str("(")?;
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{arg}")?;
            }
            f.write_str(")")
        }
        match self {
            ParsedType::Primitive(s)
            | ParsedType::Struct(s)
            | ParsedType::Union(s)
            | ParsedType::Enum(s) => write!(f, "{}", s),
            ParsedType::Pointer(inner) => {
                if let ParsedType::Function(ret_type, args) = &**inner {
                    write!(f, "{ret_type} (*)")?;
                    signature(f, args)
                } else {
                    write!(f, "{}*", inner)
                }
            }
            ParsedType::Array(inner, count) => {
                // `T[2][256]` is Array(Array(T, 256), 2): outer count first.
                let mut dims = vec![*count];
                let mut element = inner.as_ref();
                while let ParsedType::Array(next, n) = element {
                    dims.push(*n);
                    element = next.as_ref();
                }
                write!(f, "{element}")?;
                for n in dims {
                    write!(f, "[{n}]")?;
                }
                Ok(())
            }
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => write!(f, "{} : {} @ bit {}", underlying, len, pos),
            ParsedType::Function(ret_type, args) => {
                write!(f, "{ret_type} ")?;
                signature(f, args)
            }
            ParsedType::Unknown => write!(f, "<?>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub offset: u32,
    pub size: u64,
    pub type_data: ParsedType,
}

impl FieldInfo {
    /// The field's value from `raw`, the integer its storage holds: the
    /// extracted bits for a bitfield, `raw` itself otherwise.
    pub fn decode(&self, raw: u64) -> u64 {
        match &self.type_data {
            ParsedType::Bitfield { pos, len, .. } => bitfield_value(raw, *pos, *len),
            _ => raw,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub fields: HashMap<String, FieldInfo>,
    /// Width of a pointer in the PDB this layout came from: 4 for a 32-bit
    /// module (a WOW64 process's ntdll), 8 otherwise. Pointer fields are
    /// already sized by it; list links and other implicit pointers use it.
    pub pointer_size: u8,
}

impl TypeInfo {
    /// The field called `name`, spelled exactly as the PDB does.
    pub fn field(&self, name: &str) -> Result<&FieldInfo> {
        self.fields
            .get(name)
            .ok_or_else(|| Error::FieldNotFound(name.to_string()))
    }

    pub fn field_offset(&self, name: &str) -> Result<u64> {
        self.field(name).map(|f| u64::from(f.offset))
    }

    /// The fields in `dt`'s layout order: by offset, then bit position, then
    /// name, so every host lists a union's members and a bitfield group the
    /// same way.
    pub fn fields_in_order(&self) -> Vec<(&String, &FieldInfo)> {
        let mut fields: Vec<_> = self.fields.iter().collect();
        fields.sort_by_key(|(name, field)| {
            let bit = match &field.type_data {
                ParsedType::Bitfield { pos, .. } => *pos,
                _ => 0,
            };
            (field.offset, bit, *name)
        });
        fields
    }

    /// Decode the scalar leaves of this struct out of a buffer covering the
    /// whole type, returning `(field, value)` pairs in
    /// [layout order](Self::fields_in_order); the Python struct reader packs
    /// each neutral [`FieldValue`] into a Python object. Nested struct/union
    /// fields (reported by the PDB with size 0) and fields running past the
    /// buffer are skipped; read those separately with their own type.
    pub fn decode_fields(&self, buf: &[u8]) -> Vec<(String, FieldValue)> {
        let mut out = Vec::new();
        for (name, f) in self.fields_in_order() {
            let off = f.offset as usize;
            let sz = f.size as usize;
            if sz == 0 || off + sz > buf.len() {
                continue;
            }
            let slice = &buf[off..off + sz];
            let raw = le_uint(slice);
            let value = match &f.type_data {
                ParsedType::Bitfield { .. } => FieldValue::Bitfield(f.decode(raw)),
                ParsedType::Pointer(_) => FieldValue::Pointer(raw),
                _ => match sz {
                    1 | 2 | 4 | 8 => FieldValue::Int(raw),
                    _ => FieldValue::Bytes(slice.to_vec()),
                },
            };
            out.push((name.clone(), value));
        }
        out
    }
}

/// A decoded scalar field leaf, the result of [`TypeInfo::decode_fields`].
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// A 1/2/4/8-byte integer.
    Int(u64),
    /// A pointer-sized address (semantically distinct so hosts can render it as
    /// hex if they prefer).
    Pointer(u64),
    /// A bitfield already masked/shifted to its value.
    Bitfield(u64),
    /// A larger aggregate (array, embedded blob) returned verbatim.
    Bytes(Vec<u8>),
}

/// A PDB enum ([`SymbolStore::enum_def`](crate::symbols::SymbolStore::enum_def)).
#[derive(Debug)]
pub struct EnumDef {
    /// `(name, value)` in declaration order.
    pub variants: Vec<(String, i64)>,
    /// Storage width in bytes of the underlying type, when it resolves.
    pub size: Option<u64>,
}

/// Little-endian unsigned integer from up to 8 bytes.
pub fn le_uint(slice: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in slice.iter().take(8).enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

/// The low `len` bits set.
pub fn bitfield_mask(len: u8) -> u64 {
    u64::MAX
        .checked_shr(64 - u32::from(len.min(64)))
        .unwrap_or(0)
}

/// The `len`-bit field starting at bit `pos` of `raw`. Positions past the
/// word read as zero rather than overflowing the shift.
pub fn bitfield_value(raw: u64, pos: u8, len: u8) -> u64 {
    raw.checked_shr(u32::from(pos)).unwrap_or(0) & bitfield_mask(len)
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

/// Byte width of a primitive type name, as the PDB spells it or as a user
/// writes it in an expression; `None` for anything else.
pub fn primitive_size(name: &str) -> Option<u64> {
    const SIZES: &[(u64, &[&str])] = &[
        (
            1,
            &[
                "char", "schar", "uchar", "int8", "uint8", "i8", "u8", "int8_t", "uint8_t", "bool",
                "bool8", "boolean",
            ],
        ),
        (
            2,
            &[
                "wchar",
                "wchar_t",
                "char16_t",
                "short",
                "ushort",
                "short int",
                "unsigned short",
                "int16",
                "uint16",
                "i16",
                "u16",
                "int16_t",
                "uint16_t",
            ],
        ),
        (
            4,
            &[
                "long", "ulong", "int", "uint", "int32", "uint32", "i32", "u32", "int32_t",
                "uint32_t", "bool32", "char32_t", "float",
            ],
        ),
        (
            8,
            &[
                "longlong",
                "ulonglong",
                "long long",
                "unsigned long long",
                "__int64",
                "unsigned __int64",
                "int64",
                "uint64",
                "i64",
                "u64",
                "int64_t",
                "uint64_t",
                "qword",
                "size_t",
                "usize",
                "double",
            ],
        ),
        (16, &["int128", "uint128"]),
    ];
    SIZES
        .iter()
        .find(|(_, names)| names.iter().any(|known| known.eq_ignore_ascii_case(name)))
        .map(|(size, _)| *size)
}

/// Remove a module qualifier before a cross-module type or enum lookup.
pub fn unqualified_type_name(type_name: &str) -> &str {
    type_name
        .rsplit_once('!')
        .map(|(_, name)| name)
        .unwrap_or(type_name)
}

/// Return the layout name nested inside a parsed type, including the two
/// Windows ABI aggregates whose PDB representation may be primitive.
pub fn nested_layout_name(type_data: &ParsedType) -> Option<String> {
    match type_data {
        ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.clone()),
        ParsedType::Primitive(name) if is_type_name(name, LIST_ENTRY) => {
            Some(LIST_ENTRY.to_string())
        }
        ParsedType::Primitive(name) if is_type_name(name, UNICODE_STRING) => {
            Some(UNICODE_STRING.to_string())
        }
        ParsedType::Pointer(inner) | ParsedType::Array(inner, _) => nested_layout_name(inner),
        ParsedType::Bitfield { underlying, .. } => nested_layout_name(underlying),
        _ => None,
    }
}

/// Test whether a parsed type names the Windows layout `wanted`, ignoring a
/// module qualifier and the leading underscore and case that differ between
/// PDB producers.
pub fn named_type(type_data: &ParsedType, wanted: &str) -> bool {
    match type_data {
        ParsedType::Primitive(name) | ParsedType::Struct(name) | ParsedType::Union(name) => {
            is_type_name(name, wanted)
        }
        _ => false,
    }
}

/// [`named_type`] for a bare type name.
fn is_type_name(name: &str, wanted: &str) -> bool {
    unqualified_type_name(name)
        .trim_start_matches('_')
        .eq_ignore_ascii_case(wanted.trim_start_matches('_'))
}

const LIST_ENTRY: &str = "_LIST_ENTRY";
const UNICODE_STRING: &str = "_UNICODE_STRING";

/// The 64-bit Windows ABI layout of `_LIST_ENTRY` or `_UNICODE_STRING`, for
/// when no loaded PDB describes it; `None` for any other type.
pub fn abi_layout(type_name: &str) -> Option<TypeInfo> {
    let field = |name: &str, offset, size, type_data| {
        (
            name.to_string(),
            FieldInfo {
                offset,
                size,
                type_data,
            },
        )
    };
    let (name, fields) = if is_type_name(type_name, LIST_ENTRY) {
        let link = || ParsedType::Pointer(Box::new(ParsedType::Unknown));
        (
            LIST_ENTRY,
            vec![field("Flink", 0, 8, link()), field("Blink", 8, 8, link())],
        )
    } else if is_type_name(type_name, UNICODE_STRING) {
        let ushort = || ParsedType::Primitive("USHORT".to_string());
        let wchar = ParsedType::Primitive("WCHAR".to_string());
        (
            UNICODE_STRING,
            vec![
                field("Length", 0, 2, ushort()),
                field("MaximumLength", 2, 2, ushort()),
                field("Buffer", 8, 8, ParsedType::Pointer(Box::new(wchar))),
            ],
        )
    } else {
        return None;
    };
    Some(TypeInfo {
        name: name.to_string(),
        size: 16,
        fields: fields.into_iter().collect(),
        pointer_size: 8,
    })
}

/// Find a field by exact name first, then by case-insensitive name, for PDBs
/// whose spelling differs only in case from a host request.
pub fn find_field<'a>(
    type_info: &'a TypeInfo,
    requested: &str,
) -> Option<(&'a String, &'a FieldInfo)> {
    type_info.fields.get_key_value(requested).or_else(|| {
        type_info
            .fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(requested))
    })
}

#[cfg(test)]
mod tests;
