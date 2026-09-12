use std::borrow::Cow;
use std::sync::Arc;

use crate::error::Result;
use crate::expr::Expr;
use crate::symbols::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::target::UserVar;
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

const MAX_LIST_ENTRIES: usize = 4096;
const MAX_ARRAY_ELEMENTS: usize = 16;
const MAX_RECURSION_DEPTH: usize = 64;
const MAX_UNICODE_BYTES: usize = 4096;
const MAX_DL_WORDS: usize = 64;

repl_command! {
    cmd_dt;
    names: ["dt"],
    usage: "dt [-r[N]] [-a[N]] [-v] [-y] [-l <field>] [module!]<type> [address] [field-pattern...]",
    summary: "Display a type layout or decoded structure.",
    details: "-r expands nested structures, -a expands bounded arrays, -v shows field sizes, -y uses case-insensitive prefix matching, and -l walks a LIST_ENTRY field.",
    completion: Type,
}

repl_command! {
    cmd_dl;
    names: ["dl"],
    usage: "dl [-b] <address> <maxcount> [size]",
    summary: "Dump a bounded _LIST_ENTRY chain.",
    details: "The default walk follows Flink; -b follows Blink. The optional size is the number of pointer-sized words displayed per element (default 2).",
    completion: Expression,
}

repl_command! {
    cmd_list_command;
    names: ["!list"],
    usage: "!list -t [module!]<type>.<field> -x \"<commands>\" <address>",
    summary: "Run commands for every element of a typed LIST_ENTRY chain.",
    details: "The element address is available as $extret, @extret, or @$extret in each command. Walks stop at the head, repeated links, or 4096 elements.",
    completion: Expression,
}

#[derive(Debug, Clone, Default)]
struct DtOptions {
    recursive_depth: usize,
    array_limit: Option<usize>,
    verbose: bool,
    prefix_match: bool,
    list_field: Option<Vec<String>>,
    show_values: bool,
}

#[derive(Debug, Clone)]
struct ParsedDtArgs {
    type_name: String,
    address_text: Option<String>,
    field_patterns: Vec<String>,
    options: DtOptions,
}

#[derive(Debug, Clone)]
struct PathComponent {
    name: String,
    info: FieldInfo,
}

#[derive(Debug, Clone)]
struct ResolvedFieldPath {
    components: Vec<PathComponent>,
}

fn parse_depth_option(arg: &str, prefix: &str, bare: usize) -> std::result::Result<usize, String> {
    let suffix = &arg[prefix.len()..];
    if suffix.is_empty() {
        return Ok(bare);
    }
    let value = suffix
        .parse::<usize>()
        .map_err(|_| format!("invalid {} depth `{}`", prefix, suffix))?;
    Ok(value.min(MAX_RECURSION_DEPTH))
}

fn parse_array_option(arg: &str) -> std::result::Result<usize, String> {
    let suffix = &arg[2..];
    if suffix.is_empty() {
        return Ok(MAX_ARRAY_ELEMENTS);
    }
    let value = suffix
        .parse::<usize>()
        .map_err(|_| format!("invalid -a count `{}`", suffix))?;
    Ok(value.min(MAX_ARRAY_ELEMENTS))
}

fn parse_dt_args(args: &[Cow<'_, str>]) -> std::result::Result<ParsedDtArgs, String> {
    let mut options = DtOptions::default();
    let mut positional = Vec::new();
    let mut index = 0;
    let mut parse_options = true;

    while index < args.len() {
        let arg = args[index].as_ref();
        if parse_options && arg == "--" {
            parse_options = false;
            index += 1;
            continue;
        }
        if parse_options && (arg == "-r" || arg.starts_with("-r")) {
            options.recursive_depth = parse_depth_option(arg, "-r", 1)?;
            index += 1;
            continue;
        }
        if parse_options && (arg == "-a" || arg.starts_with("-a")) {
            options.array_limit = Some(parse_array_option(arg)?);
            index += 1;
            continue;
        }
        if parse_options && arg == "-v" {
            options.verbose = true;
            index += 1;
            continue;
        }
        if parse_options && arg == "-y" {
            options.prefix_match = true;
            index += 1;
            continue;
        }
        if parse_options && arg == "-l" {
            let Some(field) = args.get(index + 1).map(|value| value.as_ref()) else {
                return Err("missing field after -l".to_string());
            };
            options.list_field = Some(parse_field_path(field)?);
            index += 2;
            continue;
        }
        if parse_options && arg.starts_with('-') {
            return Err(format!("unknown dt option `{arg}`"));
        }
        positional.push(arg.to_string());
        index += 1;
    }

    let Some(type_name) = positional.first().cloned() else {
        return Err("missing type name".to_string());
    };
    Ok(ParsedDtArgs {
        type_name,
        address_text: positional.get(1).cloned(),
        field_patterns: positional.into_iter().skip(2).collect(),
        options,
    })
}

/// Parse a dotted field path without resolving it against a particular PDB.
fn parse_field_path(path: &str) -> std::result::Result<Vec<String>, String> {
    if path.is_empty() {
        return Err("field path is empty".to_string());
    }
    let mut fields = Vec::new();
    for field in path.split('.') {
        if field.is_empty()
            || !field
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            || !field
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(format!("invalid field path `{path}`"));
        }
        fields.push(field.to_string());
    }
    Ok(fields)
}

fn field_matches(name: &str, patterns: &[String], prefix_match: bool) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|pattern| {
        if prefix_match {
            name.to_ascii_lowercase()
                .starts_with(&pattern.to_ascii_lowercase())
        } else {
            crate::symbols::glob_matches(pattern, name, true)
        }
    })
}

fn unqualified_type_name(type_name: &str) -> &str {
    type_name
        .rsplit_once('!')
        .map(|(_, name)| name)
        .unwrap_or(type_name)
}

fn nested_layout_name(type_data: &ParsedType) -> Option<String> {
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

fn named_type(type_data: &ParsedType, wanted: &str) -> bool {
    match type_data {
        ParsedType::Primitive(name) | ParsedType::Struct(name) | ParsedType::Union(name) => name
            .trim_start_matches('_')
            .eq_ignore_ascii_case(wanted.trim_start_matches('_')),
        _ => false,
    }
}

fn field_sort_key(info: &FieldInfo) -> (u32, u8) {
    let bitfield_position = match &info.type_data {
        ParsedType::Bitfield { pos, .. } => *pos,
        _ => 0,
    };
    (info.offset, bitfield_position)
}

fn standard_layout_field(type_name: &str, requested: &str) -> Option<(String, FieldInfo)> {
    let normalized = type_name.trim_start_matches('_');
    let requested = requested.to_ascii_lowercase();
    if normalized.eq_ignore_ascii_case("LIST_ENTRY") {
        let (name, offset) = match requested.as_str() {
            "flink" => ("Flink", 0),
            "blink" => ("Blink", 8),
            _ => return None,
        };
        return Some((
            name.to_string(),
            FieldInfo {
                offset,
                size: 8,
                type_data: ParsedType::Pointer(Box::new(ParsedType::Unknown)),
            },
        ));
    }
    if normalized.eq_ignore_ascii_case("UNICODE_STRING") {
        let (name, offset, size, type_data) = match requested.as_str() {
            "length" => ("Length", 0, 2, ParsedType::Primitive("USHORT".to_string())),
            "maximumlength" => (
                "MaximumLength",
                2,
                2,
                ParsedType::Primitive("USHORT".to_string()),
            ),
            "buffer" => (
                "Buffer",
                8,
                8,
                ParsedType::Pointer(Box::new(ParsedType::Primitive("WCHAR".to_string()))),
            ),
            _ => return None,
        };
        return Some((
            name.to_string(),
            FieldInfo {
                offset,
                size,
                type_data,
            },
        ));
    }
    None
}

impl ReplState<'_> {
    fn lookup_type(&self, type_name: &str) -> Option<Arc<TypeInfo>> {
        self.ctx.target.symbols.find_type_across_modules(
            self.ctx.target.current_dtb(),
            unqualified_type_name(type_name),
        )
    }

    fn lookup_enum(&self, type_name: &str) -> Option<Vec<(String, i64)>> {
        self.ctx.target.symbols.find_enum_across_modules(
            self.ctx.target.current_dtb(),
            unqualified_type_name(type_name),
        )
    }

    fn parsed_type_size(&self, type_data: &ParsedType) -> usize {
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

    fn field_size(&self, field: &FieldInfo) -> usize {
        usize::try_from(field.size)
            .ok()
            .filter(|size| *size != 0)
            .unwrap_or_else(|| self.parsed_type_size(&field.type_data))
    }

    fn read_display_bytes(
        &self,
        address: VirtAddr,
        size: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        if size == 0 {
            return Err("field has no size".to_string());
        }
        let mut bytes = vec![0u8; size];
        self.ctx
            .read_masked(address, &mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    }

    fn read_display_uint(
        &self,
        address: VirtAddr,
        size: usize,
    ) -> std::result::Result<u64, String> {
        if size == 0 {
            return Err("field has no size".to_string());
        }
        if size > 8 {
            return Err(format!("scalar field is {} bytes", size));
        }
        let mut bytes = [0u8; 8];
        self.ctx
            .read_masked(address, &mut bytes[..size])
            .map_err(|error| error.to_string())?;
        Ok(le_uint(&bytes[..size]))
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
        format!(" = 0n{signed} ( {variant} )")
    }

    fn format_scalar_value(&self, address: VirtAddr, field: &FieldInfo) -> String {
        let size = self.field_size(field);
        let raw = match self.read_display_uint(address, size) {
            Ok(raw) => raw,
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        match &field.type_data {
            ParsedType::Pointer(_) => format!(" = {:#x}", raw),
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
                        " = Y".to_string()
                    } else {
                        " = N".to_string()
                    }
                } else if let ParsedType::Enum(type_name) = underlying.as_ref() {
                    self.format_enum_value(type_name, value, size)
                } else {
                    format!(" = {:#x}", value)
                }
            }
            _ => format!(" = {:#x}", raw),
        }
    }

    fn format_c_string(&self, address: VirtAddr, count: u32) -> String {
        let size = (count as usize).min(MAX_UNICODE_BYTES);
        let bytes = match self.read_display_bytes(address, size) {
            Ok(bytes) => bytes,
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let text: String = String::from_utf8_lossy(&bytes[..end])
            .chars()
            .flat_map(char::escape_default)
            .collect();
        format!(" = \"{text}\"")
    }

    fn format_unicode_string(&self, address: VirtAddr) -> String {
        let type_info = self.lookup_type("_UNICODE_STRING");
        let (length_offset, length_size, buffer_offset, buffer_size) =
            if let Some(type_info) = type_info {
                let Some((_, length_field)) = find_field(type_info.as_ref(), "Length") else {
                    return " = <unavailable: Length field not found>".to_string();
                };
                let Some((_, buffer_field)) = find_field(type_info.as_ref(), "Buffer") else {
                    return " = <unavailable: Buffer field not found>".to_string();
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
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        let buffer = match self.read_display_uint(address + buffer_offset, buffer_size) {
            Ok(buffer) => VirtAddr(buffer),
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        if length == 0 || buffer.is_zero() {
            return " = \"\"".to_string();
        }
        let bytes = match self.read_display_bytes(buffer, length) {
            Ok(bytes) => bytes,
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let text: String = String::from_utf16_lossy(&utf16)
            .chars()
            .flat_map(char::escape_default)
            .collect();
        format!(" = \"{text}\"")
    }

    fn format_list_entry(&self, address: VirtAddr) -> String {
        let (flink_offset, flink_size, blink_offset, blink_size) =
            if let Some(type_info) = self.lookup_type("_LIST_ENTRY") {
                let Some((_, flink)) = find_field(type_info.as_ref(), "Flink") else {
                    return " = <unavailable: Flink field not found>".to_string();
                };
                let Some((_, blink)) = find_field(type_info.as_ref(), "Blink") else {
                    return " = <unavailable: Blink field not found>".to_string();
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
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        let blink = match self.read_display_uint(address + blink_offset, blink_size) {
            Ok(value) => value,
            Err(error) => return format!(" = <unavailable: {error}>"),
        };
        format!(" = [ {:#x} - {:#x} ]", flink, blink)
    }

    fn field_descriptor(
        &self,
        indent: usize,
        name: &str,
        field: &FieldInfo,
        options: &DtOptions,
    ) -> String {
        let prefix = " ".repeat(indent);
        let type_name = field.type_data.to_string();
        if options.verbose {
            format!(
                "{prefix}+0x{:04x} {name} : {type_name} [size {}]",
                field.offset,
                self.field_size(field)
            )
        } else {
            format!("{prefix}+0x{:04x} {name} : {type_name}", field.offset)
        }
    }

    fn print_field_value(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        label: &str,
        options: &DtOptions,
        indent: usize,
        depth: usize,
        recurse_struct: bool,
    ) {
        match &field.type_data {
            ParsedType::Primitive(_) | ParsedType::Struct(_) | ParsedType::Union(_)
                if named_type(&field.type_data, "_UNICODE_STRING") =>
            {
                if options.show_values {
                    outln!("{}{}", label, self.format_unicode_string(address));
                } else {
                    outln!("{}", label);
                }
            }
            ParsedType::Primitive(_) | ParsedType::Struct(_) | ParsedType::Union(_)
                if named_type(&field.type_data, "_LIST_ENTRY") =>
            {
                if options.show_values {
                    outln!("{}{}", label, self.format_list_entry(address));
                } else {
                    outln!("{}", label);
                }
            }
            ParsedType::Struct(type_name) | ParsedType::Union(type_name) => {
                outln!("{}", label);
                if recurse_struct {
                    if let Some(type_info) = self.lookup_type(type_name) {
                        self.print_struct_fields(
                            type_info.as_ref(),
                            address,
                            options,
                            &[],
                            depth.saturating_sub(1),
                            indent + 2,
                        );
                    } else {
                        outln!(
                            "{}<unavailable: type {} not found>",
                            " ".repeat(indent + 2),
                            type_name
                        );
                    }
                }
            }
            ParsedType::Array(inner, count) => {
                if let Some(string_len) = field.type_data.c_string_len() {
                    if options.show_values {
                        outln!("{}{}", label, self.format_c_string(address, string_len));
                    } else {
                        outln!("{}", label);
                    }
                } else {
                    outln!("{}", label);
                    self.print_array_elements(
                        address,
                        field,
                        inner,
                        *count,
                        options,
                        indent + 2,
                        depth.saturating_sub(1),
                    );
                }
            }
            _ => {
                if options.show_values {
                    outln!("{}{}", label, self.format_scalar_value(address, field));
                } else {
                    outln!("{}", label);
                }
            }
        }
    }

    fn print_array_elements(
        &self,
        address: VirtAddr,
        field: &FieldInfo,
        inner: &ParsedType,
        count: u32,
        options: &DtOptions,
        indent: usize,
        depth: usize,
    ) {
        let max_elements = options
            .array_limit
            .unwrap_or(MAX_ARRAY_ELEMENTS)
            .min(MAX_ARRAY_ELEMENTS);
        let count_usize = count as usize;
        let shown = count_usize.min(max_elements);
        if shown == 0 {
            return;
        }
        let total_size = self.field_size(field);
        let element_size = if count_usize != 0 && total_size != 0 {
            total_size / count_usize
        } else {
            self.parsed_type_size(inner)
        };
        if element_size == 0 {
            outln!(
                "{}[array elements unavailable: element size is unknown]",
                " ".repeat(indent)
            );
            return;
        }

        for index in 0..shown {
            let element_address = address + (index.saturating_mul(element_size)) as u64;
            let element_field = FieldInfo {
                offset: 0,
                size: element_size as u64,
                type_data: inner.clone(),
            };
            let prefix = " ".repeat(indent);
            self.print_field_value(
                element_address,
                &element_field,
                &format!("{}[{}] : {}", prefix, index, inner),
                options,
                indent,
                depth,
                true,
            );
        }
        if shown < count_usize {
            outln!(
                "{}... {} array elements omitted",
                " ".repeat(indent),
                count_usize - shown
            );
        }
    }

    fn print_struct_fields(
        &self,
        type_info: &TypeInfo,
        base: VirtAddr,
        options: &DtOptions,
        patterns: &[String],
        depth: usize,
        indent: usize,
    ) {
        let mut fields: Vec<_> = type_info.fields.iter().collect();
        fields.sort_by_key(|(_, field)| field_sort_key(field));
        for (name, field) in fields {
            if !field_matches(name, patterns, options.prefix_match) {
                continue;
            }
            let address = base + field.offset as u64;
            let descriptor = self.field_descriptor(indent, name, field, options);
            self.print_field_value(
                address,
                field,
                &descriptor,
                options,
                indent,
                depth,
                depth > 0,
            );
        }
    }

    fn resolve_field_path(
        &self,
        root: &TypeInfo,
        path: &[String],
    ) -> std::result::Result<ResolvedFieldPath, String> {
        if path.is_empty() {
            return Err("field path is empty".to_string());
        }
        let mut current_type = None;
        let mut current_type_name = None;
        let mut components = Vec::with_capacity(path.len());
        for (index, requested_name) in path.iter().enumerate() {
            let (name, info) = {
                let found = if let Some(type_info) = current_type.as_deref() {
                    find_field(type_info, requested_name)
                        .map(|(name, info)| (name.to_string(), info.clone()))
                } else if let Some(type_name) = current_type_name.as_deref() {
                    standard_layout_field(type_name, requested_name)
                } else {
                    find_field(root, requested_name)
                        .map(|(name, info)| (name.to_string(), info.clone()))
                };
                let Some((name, info)) = found else {
                    return Err(format!("field `{requested_name}` not found"));
                };
                (name, info)
            };
            let next_type_name = nested_layout_name(&info.type_data);
            components.push(PathComponent { name, info });
            if index + 1 < path.len() {
                let Some(next_type_name) = next_type_name else {
                    return Err(format!(
                        "field `{requested_name}` is not a nested structure"
                    ));
                };
                if let Some(next_type) = self.lookup_type(&next_type_name) {
                    current_type = Some(next_type);
                    current_type_name = None;
                } else if standard_layout_field(&next_type_name, "Flink").is_some()
                    || standard_layout_field(&next_type_name, "Length").is_some()
                {
                    current_type = None;
                    current_type_name = Some(next_type_name);
                } else {
                    return Err(format!("nested type `{next_type_name}` not found"));
                }
            }
        }
        Ok(ResolvedFieldPath { components })
    }

    fn runtime_field_address(
        &self,
        base: VirtAddr,
        path: &ResolvedFieldPath,
    ) -> std::result::Result<(VirtAddr, FieldInfo), String> {
        let mut current = base;
        for (index, component) in path.components.iter().enumerate() {
            let field_address = current + component.info.offset as u64;
            if index + 1 == path.components.len() {
                return Ok((field_address, component.info.clone()));
            }
            if matches!(component.info.type_data, ParsedType::Pointer(_)) {
                let pointer =
                    self.read_display_uint(field_address, self.field_size(&component.info))?;
                if pointer == 0 {
                    return Err(format!("field `{}` points to null", component.name));
                }
                current = VirtAddr(pointer);
            } else {
                current = field_address;
            }
        }
        Err("field path is empty".to_string())
    }

    fn print_resolved_path(
        &self,
        root: &TypeInfo,
        base: VirtAddr,
        path: &[String],
        options: &DtOptions,
    ) {
        let resolved = match self.resolve_field_path(root, path) {
            Ok(path) => path,
            Err(error) => {
                error!("{}: {}", path.join("."), error);
                return;
            }
        };
        let (address, field) = match self.runtime_field_address(base, &resolved) {
            Ok(value) => value,
            Err(error) => {
                outln!("  {} : <unavailable: {}>", path.join("."), error);
                return;
            }
        };
        let descriptor = self.field_descriptor(2, &path.join("."), &field, options);
        self.print_field_value(
            address,
            &field,
            &descriptor,
            options,
            2,
            options.recursive_depth.max(1),
            true,
        );
    }

    fn list_offsets(
        &self,
        path: &ResolvedFieldPath,
    ) -> std::result::Result<(u64, u64, usize), String> {
        let Some(last) = path.components.last() else {
            return Err("field path is empty".to_string());
        };
        let mut link_offset = 0u64;
        if named_type(&last.info.type_data, "_LIST_ENTRY") {
            link_offset = last.info.offset as u64;
            return Ok((link_offset, link_offset, 8));
        }
        for component in &path.components[..path.components.len() - 1] {
            if matches!(component.info.type_data, ParsedType::Pointer(_)) {
                return Err("list field path cannot pass through a pointer".to_string());
            }
            link_offset = link_offset.saturating_add(component.info.offset as u64);
        }
        let next_offset = link_offset.saturating_add(last.info.offset as u64);
        let pointer_size = self.field_size(&last.info).clamp(1, 8);
        Ok((link_offset, next_offset, pointer_size))
    }

    fn collect_typed_list(
        &self,
        head: VirtAddr,
        link_offset: u64,
        next_offset: u64,
        pointer_size: usize,
    ) -> Vec<VirtAddr> {
        let mut current = head;
        if !current.is_zero()
            && self
                .read_display_uint(current, pointer_size)
                .ok()
                .is_some_and(|next| next == current.0)
        {
            return Vec::new();
        }
        let mut seen = std::collections::HashSet::new();
        let mut records = Vec::new();
        while !current.is_zero() && records.len() < MAX_LIST_ENTRIES && seen.insert(current.0) {
            let record = current - link_offset;
            records.push(record);
            let next = match self.read_display_uint(record + next_offset, pointer_size) {
                Ok(next) => next,
                Err(error) => {
                    outln!("{}: <unavailable next link: {}>", ui::addr(record.0), error);
                    break;
                }
            };
            // `dt -l ... poi(ListHead)` receives the first record's link,
            // not the LIST_ENTRY object that owns the sentinel. Recognize
            // that sentinel when its Flink points back to our starting link,
            // while retaining the ordinary explicit-head stop condition.
            let sentinel = self.is_list_sentinel(next, head.0, 0, pointer_size);
            if next == 0 || next == head.0 || sentinel {
                break;
            }
            current = VirtAddr(next);
        }
        records
    }

    fn is_list_sentinel(
        &self,
        candidate: u64,
        head: u64,
        backlink_offset: u64,
        pointer_size: usize,
    ) -> bool {
        candidate != 0
            && candidate != head
            && self
                .read_display_uint(VirtAddr(candidate) + backlink_offset, pointer_size)
                .ok()
                .is_some_and(|link| link == head)
    }

    fn cmd_dt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut parsed = match parse_dt_args(&invocation.argv) {
            Ok(parsed) => parsed,
            Err(error) => {
                if error == "missing type name" {
                    outln!("{}\n", command_help("dt"));
                } else {
                    error!("dt: {}", error);
                }
                return Ok(());
            }
        };
        let type_info = match self.lookup_type(&parsed.type_name) {
            Some(type_info) => type_info,
            None => {
                if let Some(variants) = self.lookup_enum(&parsed.type_name) {
                    outln!(
                        "enum {} ({} values)",
                        unqualified_type_name(&parsed.type_name),
                        variants.len()
                    );
                    for (name, value) in variants {
                        outln!("  {:#x}  {}", value, name);
                    }
                    outln!();
                } else {
                    error!(
                        "failed to get type information: type `{}` not found",
                        parsed.type_name
                    );
                }
                return Ok(());
            }
        };

        let address = parsed
            .address_text
            .as_deref()
            .and_then(|text| Expr::eval_with_radix(text, &self.ctx.target, self.radix).ok());
        let base = address.filter(|address| !address.is_zero());
        parsed.options.show_values = base.is_some();
        let patterns = if parsed.address_text.is_some() && address.is_some() {
            parsed.field_patterns.clone()
        } else if let Some(address_text) = parsed.address_text {
            let mut all = Vec::with_capacity(parsed.field_patterns.len() + 1);
            all.push(address_text);
            all.extend(parsed.field_patterns);
            all
        } else {
            parsed.field_patterns.clone()
        };

        outln!(
            "{} ({} bytes){}",
            type_info.name,
            type_info.size,
            base.map(|address| format!(" @ {}", ui::addr(address.0)))
                .unwrap_or_default()
        );

        if let Some(list_path) = parsed.options.list_field.as_ref() {
            let Some(head) = base else {
                error!("dt -l requires a nonzero list head address");
                return Ok(());
            };
            let resolved = match self.resolve_field_path(type_info.as_ref(), list_path) {
                Ok(path) => path,
                Err(error) => {
                    error!("dt -l {}: {}", list_path.join("."), error);
                    return Ok(());
                }
            };
            let (link_offset, next_offset, pointer_size) = match self.list_offsets(&resolved) {
                Ok(offsets) => offsets,
                Err(error) => {
                    error!("dt -l {}: {}", list_path.join("."), error);
                    return Ok(());
                }
            };
            let records = self.collect_typed_list(head, link_offset, next_offset, pointer_size);
            for record in records {
                outln!("{} @ {}", type_info.name, ui::addr(record.0));
                self.print_struct_fields(
                    type_info.as_ref(),
                    record,
                    &parsed.options,
                    &patterns,
                    parsed.options.recursive_depth,
                    2,
                );
            }
            return Ok(());
        }

        if let Some(base) = base {
            let mut path_patterns = Vec::new();
            let mut glob_patterns = Vec::new();
            let had_patterns = !patterns.is_empty();
            for pattern in patterns {
                if !pattern.contains('*') && !pattern.contains('?') && pattern.contains('.') {
                    match parse_field_path(&pattern) {
                        Ok(path) => path_patterns.push(path),
                        Err(_) => glob_patterns.push(pattern),
                    }
                } else {
                    glob_patterns.push(pattern);
                }
            }
            for path in path_patterns {
                self.print_resolved_path(type_info.as_ref(), base, &path, &parsed.options);
            }
            if !glob_patterns.is_empty() || !had_patterns {
                self.print_struct_fields(
                    type_info.as_ref(),
                    base,
                    &parsed.options,
                    &glob_patterns,
                    parsed.options.recursive_depth,
                    2,
                );
            }
        } else {
            self.print_struct_fields(
                type_info.as_ref(),
                VirtAddr(0),
                &parsed.options,
                &patterns,
                parsed.options.recursive_depth,
                2,
            );
        }
        outln!();
        Ok(())
    }

    fn cmd_dl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut positional = Vec::new();
        let mut backward = false;
        for arg in &invocation.argv {
            if arg.as_ref() == "-b" {
                backward = true;
            } else {
                positional.push(arg.as_ref());
            }
        }
        if positional.len() < 2 || positional.len() > 3 {
            outln!("{}\n", command_help("dl"));
            return Ok(());
        }
        let address = match Expr::eval_with_radix(positional[0], &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let requested = match Expr::eval_with_radix(positional[1], &self.ctx.target, self.radix) {
            Ok(count) => count.0 as usize,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let display_words = match positional.get(2) {
            Some(size) => match Expr::eval_with_radix(size, &self.ctx.target, self.radix) {
                Ok(size) if size.0 > 0 => (size.0 as usize).min(MAX_DL_WORDS),
                Ok(_) => {
                    error!("dl size must be greater than zero");
                    return Ok(());
                }
                Err(error) => {
                    error!("{}", error);
                    return Ok(());
                }
            },
            None => 2,
        };
        let limit = requested.min(MAX_LIST_ENTRIES);
        let mut current = address;
        let mut seen = std::collections::HashSet::new();
        let mut bytes = [0u8; MAX_DL_WORDS * 8];
        for _ in 0..limit {
            if current.is_zero() || !seen.insert(current.0) {
                break;
            }
            let read_words = display_words.max(2);
            let width = read_words * 8;
            if let Err(error) = self.ctx.read_masked(current, &mut bytes[..width]) {
                outln!("{}: <unavailable: {}>", ui::addr(current.0), error);
                break;
            }
            let first = le_uint(&bytes[..8]);
            let second = le_uint(&bytes[8..16]);
            let words = (0..display_words)
                .map(|index| format!("{:#x}", le_uint(&bytes[index * 8..index * 8 + 8])))
                .collect::<Vec<_>>();
            outln!("{}  {}", ui::addr(current.0), words.join(" "));
            let next = if backward { second } else { first };
            let sentinel = self.is_list_sentinel(next, address.0, if backward { 8 } else { 0 }, 8);
            if next == 0 || next == address.0 || sentinel {
                break;
            }
            current = VirtAddr(next);
        }
        Ok(())
    }

    fn cmd_list_command(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut type_field = None;
        let mut commands = None;
        let mut positional = Vec::new();
        let mut index = 0;
        while index < invocation.argv.len() {
            match invocation.arg(index).unwrap_or_default() {
                "-t" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("!list: missing type after -t");
                        return Ok(());
                    };
                    type_field = Some(value.to_string());
                    index += 2;
                }
                "-x" => {
                    let Some(value) = invocation.arg(index + 1) else {
                        error!("!list: missing commands after -x");
                        return Ok(());
                    };
                    commands = Some(value.to_string());
                    index += 2;
                }
                arg if arg.starts_with('-') => {
                    error!("!list: unknown option `{arg}`");
                    return Ok(());
                }
                arg => {
                    positional.push(arg.to_string());
                    index += 1;
                }
            }
        }
        let Some(type_field) = type_field else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        let Some(commands) = commands else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        let Some(address_text) = positional.first() else {
            outln!("{}\n", command_help("!list"));
            return Ok(());
        };
        if positional.len() > 1 {
            error!("!list accepts one list head address");
            return Ok(());
        }
        let Some((type_name, field_name)) = type_field.rsplit_once('.') else {
            error!("!list -t expects [module!]<type>.<field>");
            return Ok(());
        };
        let path = match parse_field_path(field_name) {
            Ok(path) => path,
            Err(error) => {
                error!("!list: {}", error);
                return Ok(());
            }
        };
        let type_info = match self.lookup_type(type_name) {
            Some(type_info) => type_info,
            None => {
                error!("!list: type `{}` not found", type_name);
                return Ok(());
            }
        };
        let head = match Expr::eval_with_radix(address_text, &self.ctx.target, self.radix) {
            Ok(address) if !address.is_zero() => address,
            Ok(_) => {
                error!("!list requires a nonzero list head address");
                return Ok(());
            }
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
        let resolved = match self.resolve_field_path(type_info.as_ref(), &path) {
            Ok(path) => path,
            Err(error) => {
                error!("!list -t {}: {}", type_field, error);
                return Ok(());
            }
        };
        let (link_offset, next_offset, pointer_size) = match self.list_offsets(&resolved) {
            Ok(offsets) => offsets,
            Err(error) => {
                error!("!list -t {}: {}", type_field, error);
                return Ok(());
            }
        };
        let first = match self.read_display_uint(head, pointer_size) {
            Ok(first) => VirtAddr(first),
            Err(error) => {
                error!("!list: failed to read list head: {}", error);
                return Ok(());
            }
        };
        let records = self.collect_typed_list(first, link_offset, next_offset, pointer_size);
        let command = commands.replace("@$extret", "@extret");
        for record in records {
            self.ctx.target.user_vars.insert(
                "extret".to_string(),
                UserVar {
                    value: record.0,
                    source: "!list element".to_string(),
                },
            );
            match self.dispatch_line(&command) {
                Ok(Flow::Quit) => break,
                Ok(Flow::Continue | Flow::Denied) => {}
                Err(error) => {
                    error!("!list command failed at {}: {}", ui::addr(record.0), error);
                    break;
                }
            }
        }
        Ok(())
    }
}

fn find_field<'a>(type_info: &'a TypeInfo, requested: &str) -> Option<(&'a String, &'a FieldInfo)> {
    type_info.fields.get_key_value(requested).or_else(|| {
        type_info
            .fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(requested))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_path_parser_accepts_dotted_names_and_rejects_empty_segments() {
        assert_eq!(
            parse_field_path("ActiveProcessLinks.Flink").unwrap(),
            vec!["ActiveProcessLinks", "Flink"]
        );
        assert_eq!(parse_field_path("Pcb.Header.Type").unwrap().len(), 3);
        assert!(parse_field_path(".Flink").is_err());
        assert!(parse_field_path("Flink.").is_err());
        assert!(parse_field_path("Links..Flink").is_err());
    }
}
