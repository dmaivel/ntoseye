//! Typed field decoding shared by REPL commands and DAP variables.

#[cfg(test)]
use std::iter::repeat_n;
use std::result;
use std::sync::Arc;

use crate::session::Session;
use crate::symbols::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::types::VirtAddr;

/// Default console array limit; protocol clients request bounded windows.
pub const MAX_ARRAY_ELEMENTS: usize = 16;

/// Maximum number of bytes read while rendering either kind of string, keeping
/// malformed guest lengths from causing an unbounded host allocation.
const MAX_UNICODE_BYTES: usize = 4096;

/// Bound rendered text separately from guest-controlled string lengths.
const MAX_STRING_CHARS: usize = 256;

/// A host-neutral view over PDB type layouts and the target bytes they decode.
pub struct TypeView<'a> {
    session: &'a Session,
}

/// A decoded field ready for a host to present, with an optional child
/// expansion.
#[derive(Debug, Clone)]
pub struct FieldView {
    /// The PDB field name, or an indexed name for an array child.
    pub name: String,
    /// The PDB-rendered type spelling used by both host presentations.
    pub type_name: String,
    /// The guest address from which this field was decoded, when known.
    pub address: Option<VirtAddr>,
    /// The bare rendered value, without a host-specific separator or prefix.
    pub value: String,
    /// The child layout a host may request next, if this value is expandable.
    pub expand: Option<Expand>,
}

/// A typed child expansion for a host UI to materialize on demand.
#[derive(Debug, Clone)]
pub enum Expand {
    /// Expand a struct or union at `address` using the named PDB layout.
    Fields {
        /// The layout name hosts pass back to [`TypeView::lookup_type`].
        type_name: String,
        /// The guest base address of the layout.
        address: VirtAddr,
    },
    /// Expand bounded array elements using one element layout and stride.
    Elements {
        /// The parsed type of each child element.
        element: ParsedType,
        /// The total number of elements in the source array.
        count: u32,
        /// The byte stride between adjacent elements.
        element_size: usize,
        /// The guest base address of the source array.
        address: VirtAddr,
    },
}

impl<'a> TypeView<'a> {
    pub fn new(session: &'a Session) -> Self {
        Self { session }
    }

    /// Resolve a PDB type across loaded modules using the target's current
    /// DTB, the same lookup used by `dt` and the DAP variables tree. A
    /// `module!` qualifier selects the module (`ntdll32!_PEB`).
    pub fn lookup_type(&self, type_name: &str) -> Option<Arc<TypeInfo>> {
        self.session
            .target
            .symbols
            .find_type_across_modules(self.session.target.current_dtb(), type_name)
    }

    /// Resolve enum variants across loaded modules using the target's current
    /// DTB, so enum values have the same symbolic text in every host.
    pub fn lookup_enum(&self, type_name: &str) -> Option<Vec<(String, i64)>> {
        self.session
            .target
            .symbols
            .find_enum_across_modules(self.session.target.current_dtb(), type_name)
    }

    /// Compute a parsed type's byte size using the target's PDB layouts, as
    /// shared by scalar decoding and array-child stride calculation.
    pub fn parsed_type_size(&self, type_data: &ParsedType) -> usize {
        match type_data {
            ParsedType::Primitive(name) => match name.to_ascii_lowercase().as_str() {
                "char" | "uchar" | "int8" | "uint8" | "int8_t" | "uint8_t" | "boolean" | "bool" => {
                    1
                }
                "wchar" | "ushort" | "short" | "uint16" | "int16" | "int16_t" | "uint16_t" => 2,
                "ulong" | "long" | "uint" | "int" | "uint32" | "int32" | "int32_t" | "uint32_t"
                | "float" => 4,
                "__int64" | "unsigned __int64" | "longlong" | "ulonglong" | "uint64" | "int64"
                | "int64_t" | "uint64_t" | "double" => 8,
                _ => 0,
            },
            ParsedType::Pointer(_) | ParsedType::Function(_, _) => 8,
            ParsedType::Array(inner, count) => {
                self.parsed_type_size(inner).saturating_mul(*count as usize)
            }
            ParsedType::Bitfield { underlying, .. } => self.parsed_type_size(underlying),
            ParsedType::Struct(name) | ParsedType::Union(name) => self
                .lookup_type(name)
                .map(|type_info| type_info.size)
                .unwrap_or(0),
            ParsedType::Enum(_) => 4,
            ParsedType::Unknown => 0,
        }
    }

    /// Return a field's explicit PDB size, falling back to its parsed type
    /// size when the PDB reports zero, as `dt` has always done.
    pub fn field_size(&self, field: &FieldInfo) -> usize {
        usize::try_from(field.size)
            .ok()
            .filter(|size| *size != 0)
            .unwrap_or_else(|| self.parsed_type_size(&field.type_data))
    }

    /// Decode one field into the bare value text shared by the REPL and DAP.
    /// Aggregates intentionally return an empty value because hosts expand
    /// them as children instead of inventing a scalar summary.
    pub fn value_text(&self, address: VirtAddr, field: &FieldInfo) -> String {
        self.value_and_raw(address, field).0
    }

    /// The bare value text plus the raw scalar it decoded from, when the field
    /// holds one. A caller that needs both (a pointer's text and the pointee
    /// its expansion opens) reads the field once instead of twice.
    pub fn value_and_raw(&self, address: VirtAddr, field: &FieldInfo) -> (String, Option<u64>) {
        match &field.type_data {
            ParsedType::Primitive(_) | ParsedType::Struct(_) | ParsedType::Union(_)
                if named_type(&field.type_data, "_UNICODE_STRING") =>
            {
                (self.format_unicode_string(address, &field.type_data), None)
            }
            ParsedType::Primitive(_) | ParsedType::Struct(_) | ParsedType::Union(_)
                if named_type(&field.type_data, "_LIST_ENTRY") =>
            {
                (self.format_list_entry(address, &field.type_data), None)
            }
            ParsedType::Array(..) => (
                field
                    .type_data
                    .c_string_len()
                    .map_or_else(String::new, |count| self.format_c_string(address, count)),
                None,
            ),
            ParsedType::Struct(_) | ParsedType::Union(_) => (String::new(), None),
            _ => {
                let size = self.field_size(field);
                match self.read_display_uint(address, size) {
                    Ok(raw) => (
                        self.format_scalar_raw(raw, size, &field.type_data),
                        Some(raw),
                    ),
                    Err(error) => (format!("<unavailable: {error}>"), None),
                }
            }
        }
    }

    /// Format an evaluated scalar, including register-held and immediate values,
    /// using the same enum, pointer, and bitfield formatting as memory fields.
    pub fn scalar_text(&self, raw: u64, type_data: &ParsedType, byte_size: Option<u64>) -> String {
        let size = byte_size
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size > 0)
            .unwrap_or_else(|| self.parsed_type_size(type_data));
        self.format_scalar_raw(raw, size, type_data)
    }

    /// Decide whether a host can open a typed value and return the child
    /// description, covering pointees and bounded non-string arrays.
    pub fn expand_for(
        &self,
        type_data: &ParsedType,
        address: Option<VirtAddr>,
        value: Option<u64>,
    ) -> Option<Expand> {
        self.expand_for_with_size(type_data, address, value, None)
    }

    /// Decide expansion using a caller-provided total byte size when one is
    /// already known (for example, from an expression value). PDB array
    /// recipes occasionally omit a nested layout's size; using the evaluated
    /// width keeps element addresses correct.
    pub fn expand_for_with_size(
        &self,
        type_data: &ParsedType,
        address: Option<VirtAddr>,
        value: Option<u64>,
        byte_size: Option<u64>,
    ) -> Option<Expand> {
        match type_data {
            // An aggregate opens even when it also renders a value of its own
            // (a `_UNICODE_STRING` answers "what does it say" in the value and
            // "how is it stored" in the children).
            ParsedType::Struct(_) | ParsedType::Union(_) => {
                let address = address?;
                let type_name = nested_layout_name(type_data)?;
                self.lookup_type(&type_name)?;
                Some(Expand::Fields { type_name, address })
            }
            ParsedType::Pointer(inner) => {
                let pointee = match value {
                    Some(value) => value,
                    None => {
                        let address = address?;
                        self.read_display_uint(address, self.parsed_type_size(type_data))
                            .ok()?
                    }
                };
                if pointee == 0 {
                    return None;
                }
                let pointee_address = VirtAddr(pointee);
                match inner.as_ref() {
                    ParsedType::Struct(_) | ParsedType::Union(_) | ParsedType::Primitive(_) => {
                        let type_name = nested_layout_name(inner)?;
                        self.lookup_type(&type_name)?;
                        Some(Expand::Fields {
                            type_name,
                            address: pointee_address,
                        })
                    }
                    ParsedType::Array(element, count)
                        if *count > 0 && inner.as_ref().c_string_len().is_none() =>
                    {
                        let element_size =
                            self.element_stride(self.parsed_type_size(inner), element, *count)?;
                        Some(Expand::Elements {
                            element: element.as_ref().clone(),
                            count: *count,
                            element_size,
                            address: pointee_address,
                        })
                    }
                    _ => None,
                }
            }
            ParsedType::Array(inner, count)
                if *count > 0 && address.is_some() && type_data.c_string_len().is_none() =>
            {
                let total_size = byte_size
                    .and_then(|size| usize::try_from(size).ok())
                    .filter(|size| *size != 0)
                    .unwrap_or_else(|| self.parsed_type_size(type_data));
                let element_size = self.element_stride(total_size, inner, *count)?;
                Some(Expand::Elements {
                    element: inner.as_ref().clone(),
                    count: *count,
                    element_size,
                    address: address?,
                })
            }
            _ => None,
        }
    }

    /// The byte stride between adjacent array elements: the aggregate's own
    /// size divided by its count when the PDB reports one, else the element
    /// layout's size. `None` when neither yields a usable stride.
    pub fn element_stride(
        &self,
        total_size: usize,
        element: &ParsedType,
        count: u32,
    ) -> Option<usize> {
        let stride = if total_size != 0 && count != 0 {
            total_size / count as usize
        } else {
            self.parsed_type_size(element)
        };
        (stride != 0).then_some(stride)
    }

    /// Decode fields in layout order.
    pub fn fields(&self, type_info: &TypeInfo, base: VirtAddr) -> Vec<FieldView> {
        let mut fields: Vec<_> = type_info.fields.iter().collect();
        fields.sort_by_key(|(_, field)| field_sort_key(field));
        fields
            .into_iter()
            .map(|(name, field)| {
                let address = base + field.offset as u64;
                let (value, raw) = self.value_and_raw(address, field);
                FieldView {
                    name: name.clone(),
                    type_name: field.type_data.to_string(),
                    address: Some(address),
                    value,
                    expand: self.expand_for(&field.type_data, Some(address), raw),
                }
            })
            .collect()
    }

    /// Indexed child rows starting at `start`, for a caller paging through an
    /// array rather than displaying its head. Element names carry their real
    /// index, so a window is self-describing.
    pub fn elements_from(
        &self,
        address: VirtAddr,
        element: &ParsedType,
        count: u32,
        element_size: usize,
        start: usize,
        limit: usize,
    ) -> Vec<FieldView> {
        if element_size == 0 || start >= count as usize {
            return Vec::new();
        }
        let shown = (count as usize - start).min(limit);
        let element_field = FieldInfo {
            offset: 0,
            size: element_size as u64,
            type_data: element.clone(),
        };
        let type_name = element.to_string();
        (start..start + shown)
            .map(|index| {
                let element_address = address + (index.saturating_mul(element_size)) as u64;
                let (value, raw) = self.value_and_raw(element_address, &element_field);
                FieldView {
                    name: format!("[{index}]"),
                    type_name: type_name.clone(),
                    address: Some(element_address),
                    value,
                    expand: self.expand_for(element, Some(element_address), raw),
                }
            })
            .collect()
    }

    /// Read a little-endian unsigned scalar of `size` bytes, for the
    /// formatters here and the REPL's list walking.
    pub fn read_display_uint(&self, address: VirtAddr, size: usize) -> result::Result<u64, String> {
        if size == 0 {
            return Err("field has no size".to_string());
        }
        if size > 8 {
            return Err(format!("scalar field is {size} bytes"));
        }
        let mut bytes = [0u8; 8];
        self.session
            .read_masked(address, &mut bytes[..size])
            .map_err(|error| error.to_string())?;
        Ok(le_uint(&bytes[..size]))
    }

    pub fn read_display_bytes(
        &self,
        address: VirtAddr,
        size: usize,
    ) -> result::Result<Vec<u8>, String> {
        if size == 0 {
            return Err("field has no size".to_string());
        }
        let mut bytes = vec![0u8; size];
        self.session
            .read_masked(address, &mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    }

    fn format_enum_value(&self, type_name: &str, raw: u64, size: usize) -> String {
        let signed = match size {
            1 => raw as i8 as i64,
            2 => raw as i16 as i64,
            4 => raw as i32 as i64,
            _ => raw as i64,
        };
        let variant = self
            .lookup_enum(type_name)
            .and_then(|variants| {
                variants
                    .into_iter()
                    .find(|(_, value)| *value == signed)
                    .map(|(name, _)| name)
            })
            .unwrap_or_else(|| "?".to_string());
        format!("0n{signed} ( {variant} )")
    }

    fn format_scalar_raw(&self, raw: u64, size: usize, type_data: &ParsedType) -> String {
        match type_data {
            ParsedType::Pointer(_) => format!("{raw:#x}"),
            ParsedType::Enum(type_name) => self.format_enum_value(type_name, raw, size),
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => {
                let mask = if *len == 0 {
                    0
                } else if *len >= 64 {
                    u64::MAX
                } else {
                    (1u64 << len) - 1
                };
                let value = if *pos >= 64 { 0 } else { (raw >> pos) & mask };
                if *len == 1 {
                    if value == 1 {
                        "Y".to_string()
                    } else {
                        "N".to_string()
                    }
                } else if let ParsedType::Enum(type_name) = underlying.as_ref() {
                    self.format_enum_value(type_name, value, size)
                } else {
                    format!("{value:#x}")
                }
            }
            _ => format!("{raw:#x}"),
        }
    }

    fn format_c_string(&self, address: VirtAddr, count: u32) -> String {
        let size = (count as usize).min(MAX_UNICODE_BYTES);
        let bytes = match self.read_display_bytes(address, size) {
            Ok(bytes) => bytes,
            Err(error) => return format!("<unavailable: {error}>"),
        };
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        quote_bounded(&String::from_utf8_lossy(&bytes[..end]))
    }

    /// `type_data` is the field's own type: its (possibly `module!`-qualified)
    /// name picks the layout, so a 32-bit module's 4-byte `Buffer` is read as
    /// such.
    fn format_unicode_string(&self, address: VirtAddr, type_data: &ParsedType) -> String {
        let type_info = nested_layout_name(type_data).and_then(|name| self.lookup_type(&name));
        let (length_offset, length_size, buffer_offset, buffer_size) =
            if let Some(type_info) = type_info {
                let Some((_, length_field)) = find_field(type_info.as_ref(), "Length") else {
                    return "<unavailable: Length field not found>".to_string();
                };
                let Some((_, buffer_field)) = find_field(type_info.as_ref(), "Buffer") else {
                    return "<unavailable: Buffer field not found>".to_string();
                };
                (
                    length_field.offset as u64,
                    self.field_size(length_field),
                    buffer_field.offset as u64,
                    self.field_size(buffer_field),
                )
            } else {
                // These offsets are stable for the Windows ABI and let a PDB
                // represent a string field as a primitive aggregate.
                (0, 2, 8, 8)
            };
        let length = match self.read_display_uint(address + length_offset, length_size) {
            Ok(length) => (length as usize).min(MAX_UNICODE_BYTES) & !1,
            Err(error) => return format!("<unavailable: {error}>"),
        };
        let buffer = match self.read_display_uint(address + buffer_offset, buffer_size) {
            Ok(buffer) => VirtAddr(buffer),
            Err(error) => return format!("<unavailable: {error}>"),
        };
        if length == 0 || buffer.is_zero() {
            return "\"\"".to_string();
        }
        let bytes = match self.read_display_bytes(buffer, length) {
            Ok(bytes) => bytes,
            Err(error) => return format!("<unavailable: {error}>"),
        };
        let utf16: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes(*chunk))
            .collect();
        quote_bounded(&String::from_utf16_lossy(&utf16))
    }

    fn format_list_entry(&self, address: VirtAddr, type_data: &ParsedType) -> String {
        let (flink_offset, flink_size, blink_offset, blink_size) = if let Some(type_info) =
            nested_layout_name(type_data).and_then(|name| self.lookup_type(&name))
        {
            let Some((_, flink)) = find_field(type_info.as_ref(), "Flink") else {
                return "<unavailable: Flink field not found>".to_string();
            };
            let Some((_, blink)) = find_field(type_info.as_ref(), "Blink") else {
                return "<unavailable: Blink field not found>".to_string();
            };
            (
                flink.offset as u64,
                self.field_size(flink),
                blink.offset as u64,
                self.field_size(blink),
            )
        } else {
            (0, 8, 8, 8)
        };
        let flink = match self.read_display_uint(address + flink_offset, flink_size) {
            Ok(value) => value,
            Err(error) => return format!("<unavailable: {error}>"),
        };
        let blink = match self.read_display_uint(address + blink_offset, blink_size) {
            Ok(value) => value,
            Err(error) => return format!("<unavailable: {error}>"),
        };
        format!("[ {flink:#x} - {blink:#x} ]")
    }
}

/// Quote and escape a decoded guest string, stopping after
/// [`MAX_STRING_CHARS`]. A truncated string carries the trailing `...` that
/// `da`/`du` use, so a clamped value is never mistaken for the whole string.
fn quote_bounded(text: &str) -> String {
    let mut escaped = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index == MAX_STRING_CHARS {
            return format!("\"{escaped}\"...");
        }
        escaped.extend(ch.escape_default());
    }
    format!("\"{escaped}\"")
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
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::session::session_over_memory;

    #[test]
    fn a_garbage_string_length_cannot_size_the_rendered_value() {
        let mut memory = vec![0u8; 0x40];
        // Length = 0xffff, MaximumLength = 0xffff, Buffer = 0x1040.
        memory[0..2].copy_from_slice(&0xffffu16.to_le_bytes());
        memory[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        memory[8..16].copy_from_slice(&0x1040u64.to_le_bytes());
        // Unreadable-as-text UTF-16 at the buffer, repeated past the bound.
        memory.extend(repeat_n(0x01u8, 0x2000));
        let session = session_over_memory(0x1000, &memory);
        let view = TypeView::new(&session);

        let value = view.value_text(
            VirtAddr(0x1000),
            &FieldInfo {
                offset: 0,
                size: 16,
                type_data: ParsedType::Struct("_UNICODE_STRING".to_string()),
            },
        );

        assert!(value.ends_with("\"..."), "{value}");
        assert_eq!(value.matches("\\u{").count(), MAX_STRING_CHARS);
    }

    #[test]
    fn a_short_string_is_rendered_whole() {
        assert_eq!(
            quote_bounded("\\Driver\\PdbProbe"),
            "\"\\\\Driver\\\\PdbProbe\""
        );
    }

    #[test]
    fn bitfields_sort_by_position_and_fields_resolve_case_insensitively() {
        assert_eq!(unqualified_type_name("nt!_EPROCESS"), "_EPROCESS");

        // PDB reports both bitfields at offset 0, so only the bit position
        // orders them; `dt` prints the low bit first.
        let low = FieldInfo {
            offset: 0,
            size: 1,
            type_data: ParsedType::Bitfield {
                underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
                pos: 7,
                len: 1,
            },
        };
        let high = FieldInfo {
            offset: 0,
            size: 1,
            type_data: ParsedType::Bitfield {
                underlying: Box::new(ParsedType::Primitive("UCHAR".to_string())),
                pos: 0,
                len: 1,
            },
        };
        assert!(field_sort_key(&high) < field_sort_key(&low));

        let mut fields = HashMap::new();
        fields.insert("Value".to_string(), low);
        let info = TypeInfo {
            name: "_NODE".to_string(),
            pointer_size: 8,
            size: 1,
            fields,
        };
        assert_eq!(
            find_field(&info, "value").map(|(name, _)| name.as_str()),
            Some("Value")
        );
    }

    /// A field typed with a 32-bit module's `_UNICODE_STRING` (as a WOW64
    /// process's ntdll layouts name it) reads its 4-byte `Buffer`; the
    /// kernel's 8-byte layout would swallow the neighbouring field.
    #[test]
    fn qualified_unicode_string_reads_the_pointer_at_its_own_width() {
        let mut memory = [0u8; 0x40];
        memory[0..2].copy_from_slice(&4u16.to_le_bytes());
        memory[4..8].copy_from_slice(&0x1020u32.to_le_bytes());
        memory[8..12].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        memory[0x20..0x24].copy_from_slice(
            &"ok"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        let unicode = |pointer_size: u8, buffer_offset: u32| TypeInfo {
            name: "_UNICODE_STRING".to_string(),
            pointer_size,
            size: 2 * usize::from(pointer_size),
            fields: [
                (
                    "Length".to_string(),
                    FieldInfo {
                        offset: 0,
                        size: 2,
                        type_data: ParsedType::Primitive("USHORT".to_string()),
                    },
                ),
                (
                    "Buffer".to_string(),
                    FieldInfo {
                        offset: buffer_offset,
                        size: u64::from(pointer_size),
                        type_data: ParsedType::Pointer(Box::new(ParsedType::Primitive(
                            "WCHAR".to_string(),
                        ))),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, vec![unicode(8, 8)], &[]);
        session
            .target
            .symbols
            .inject_module_for_test(2, vec![unicode(4, 4)], &[]);
        session
            .target
            .symbols
            .register_module_for_test(2, "ntdll32", dtb);
        let view = TypeView::new(&session);

        let field = |type_name: &str| FieldInfo {
            offset: 0,
            size: 0,
            type_data: ParsedType::Struct(type_name.to_string()),
        };
        assert_eq!(
            view.value_text(VirtAddr(0x1000), &field("ntdll32!_UNICODE_STRING")),
            "\"ok\""
        );
        assert!(
            view.value_text(VirtAddr(0x1000), &field("_UNICODE_STRING"))
                .starts_with("<unavailable")
        );
    }

    #[test]
    fn values_are_bare_and_expansions_use_shared_array_bound() {
        let mut memory = [0u8; 0x80];
        memory[0] = 0x2a;
        memory[8..16].copy_from_slice(&0x1040u64.to_le_bytes());
        memory[0x20..0x23].copy_from_slice(b"abc");
        let session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_NODE".to_string(),
                pointer_size: 8,
                size: 1,
                fields: HashMap::new(),
            }],
            &[],
        );
        let view = TypeView::new(&session);

        let scalar = FieldInfo {
            offset: 0,
            size: 1,
            type_data: ParsedType::Primitive("UCHAR".to_string()),
        };
        assert_eq!(view.value_text(VirtAddr(0x1000), &scalar), "0x2a");

        let pointer = ParsedType::Pointer(Box::new(ParsedType::Struct("_NODE".to_string())));
        let pointer_field = FieldInfo {
            offset: 0,
            size: 8,
            type_data: pointer.clone(),
        };
        assert_eq!(view.value_text(VirtAddr(0x1008), &pointer_field), "0x1040");
        assert!(matches!(
            view.expand_for(&pointer, Some(VirtAddr(0x1008)), None),
            Some(Expand::Fields { type_name, address })
                if type_name == "_NODE" && address == VirtAddr(0x1040)
        ));
        assert!(
            view.expand_for(
                &ParsedType::Struct("_MISSING".to_string()),
                Some(VirtAddr(0x1000)),
                None,
            )
            .is_none()
        );

        let string_array =
            ParsedType::Array(Box::new(ParsedType::Primitive("UCHAR".to_string())), 3);
        let string_field = FieldInfo {
            offset: 0,
            size: 3,
            type_data: string_array.clone(),
        };
        assert_eq!(view.value_text(VirtAddr(0x1020), &string_field), "\"abc\"");
        assert!(
            view.expand_for(&string_array, Some(VirtAddr(0x1020)), None)
                .is_none()
        );

        let elements = view.elements_from(
            VirtAddr(0x1000),
            &ParsedType::Primitive("UCHAR".to_string()),
            32,
            1,
            0,
            MAX_ARRAY_ELEMENTS,
        );
        assert_eq!(elements.len(), MAX_ARRAY_ELEMENTS);
        assert_eq!(elements[0].name, "[0]");
        assert_eq!(elements[0].address, Some(VirtAddr(0x1000)));
        assert_eq!(elements[0].value, "0x2a");
        // A window past the end of the array yields nothing rather than
        // wrapping to the head.
        assert!(
            view.elements_from(
                VirtAddr(0x1000),
                &ParsedType::Primitive("UCHAR".to_string()),
                32,
                1,
                32,
                MAX_ARRAY_ELEMENTS,
            )
            .is_empty()
        );
        // A zero stride is unusable, so no rows are invented for it.
        assert!(
            view.elements_from(
                VirtAddr(0x1000),
                &ParsedType::Primitive("UCHAR".to_string()),
                1,
                0,
                0,
                MAX_ARRAY_ELEMENTS,
            )
            .is_empty()
        );
    }
}
