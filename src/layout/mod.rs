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
        match self {
            ParsedType::Primitive(s)
            | ParsedType::Struct(s)
            | ParsedType::Union(s)
            | ParsedType::Enum(s) => write!(f, "{}", s),
            ParsedType::Pointer(inner) => {
                if let ParsedType::Function(ret_type, args) = &**inner {
                    write!(f, "{} (*)(", ret_type)?;
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", arg)?;
                    }
                    write!(f, ")")
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
                write!(f, "{} (", ret_type)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            ParsedType::Unknown => write!(f, "<?>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub offset: u32,
    #[allow(dead_code)]
    pub size: u64,
    pub type_data: ParsedType,
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
    pub fn field_offset<S>(&self, field_name: S) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        self.fields
            .get(field_name.as_ref())
            .ok_or(Error::FieldNotFound(field_name.into()))
            .map(|f| f.offset as u64)
    }

    /// Decode the scalar leaves of this struct out of a buffer covering the whole
    /// type, returning `(field, value)` pairs sorted by offset. The field-decoding
    /// rules shared by the pyo3 and MCP struct readers; each host packs the neutral
    /// [`FieldValue`] into its own form. Nested struct/union fields (reported by
    /// the PDB with size 0) and fields running past the buffer are skipped; read
    /// those separately with their own type.
    pub fn decode_fields(&self, buf: &[u8]) -> Vec<(String, FieldValue)> {
        let mut out: Vec<(u32, String, FieldValue)> = Vec::new();
        for (name, f) in self.fields.iter() {
            let off = f.offset as usize;
            let sz = f.size as usize;
            if sz == 0 || off + sz > buf.len() {
                continue;
            }
            let slice = &buf[off..off + sz];
            let value = match &f.type_data {
                ParsedType::Bitfield { pos, len, .. } => {
                    let raw = le_uint(slice);
                    let mask = if *len >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << len) - 1
                    };
                    FieldValue::Bitfield((raw >> pos) & mask)
                }
                ParsedType::Pointer(_) => FieldValue::Pointer(le_uint(slice)),
                _ => match sz {
                    1 | 2 | 4 | 8 => FieldValue::Int(le_uint(slice)),
                    _ => FieldValue::Bytes(slice.to_vec()),
                },
            };
            out.push((f.offset, name.clone(), value));
        }
        out.sort_by_key(|(off, _, _)| *off);
        out.into_iter()
            .map(|(_, name, value)| (name, value))
            .collect()
    }
}

/// A decoded scalar field leaf, the neutral result of [`TypeInfo::decode_fields`].
/// Hosts render this into their own representation (Python objects / JSON).
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

/// Little-endian unsigned integer from up to 8 bytes, shared by the
/// struct/bitfield decoders.
pub fn le_uint(slice: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in slice.iter().take(8).enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

/// A PDB enum ([`SymbolStore::enum_def`](crate::symbols::SymbolStore::enum_def)).
#[derive(Debug)]
pub struct EnumDef {
    /// `(name, value)` in declaration order.
    pub variants: Vec<(String, i64)>,
    /// Storage width in bytes of the underlying type, when it resolves.
    pub size: Option<u64>,
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
        ParsedType::Primitive(name)
            if name
                .trim_start_matches('_')
                .eq_ignore_ascii_case("LIST_ENTRY") =>
        {
            Some("_LIST_ENTRY".to_string())
        }
        ParsedType::Primitive(name)
            if name
                .trim_start_matches('_')
                .eq_ignore_ascii_case("UNICODE_STRING") =>
        {
            Some("_UNICODE_STRING".to_string())
        }
        ParsedType::Pointer(inner) | ParsedType::Array(inner, _) => nested_layout_name(inner),
        ParsedType::Bitfield { underlying, .. } => nested_layout_name(underlying),
        _ => None,
    }
}

/// Test whether a parsed type names a requested Windows layout, ignoring the
/// conventional leading underscore and case used by different PDB producers.
pub fn named_type(type_data: &ParsedType, wanted: &str) -> bool {
    match type_data {
        ParsedType::Primitive(name) | ParsedType::Struct(name) | ParsedType::Union(name) => {
            unqualified_type_name(name)
                .trim_start_matches('_')
                .eq_ignore_ascii_case(wanted.trim_start_matches('_'))
        }
        _ => false,
    }
}

/// Sort fields by byte offset and then by bitfield position, matching `dt`'s
/// stable layout order across hosts.
pub fn field_sort_key(info: &FieldInfo) -> (u32, u8) {
    let bitfield_position = match &info.type_data {
        ParsedType::Bitfield { pos, .. } => *pos,
        _ => 0,
    };
    (info.offset, bitfield_position)
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
