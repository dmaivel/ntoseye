//! Type lookup: resolving PDB type records into [`TypeInfo`] layouts and enum
//! definitions, scoped to the modules of an address space.

use super::SymbolStore;
use crate::{
    layout::{EnumDef, FieldInfo, ParsedType, TypeInfo},
    types::Dtb,
};
use pdb2::{FallibleIterator, PrimitiveKind, TypeData, TypeFinder, TypeIndex};
use std::{collections::HashMap, sync::Arc};

/// A pdb2 enum-constant value, widened to `i64` (enum tags are small).
fn variant_to_i64(v: &pdb2::Variant) -> i64 {
    match *v {
        pdb2::Variant::U8(x) => x as i64,
        pdb2::Variant::U16(x) => x as i64,
        pdb2::Variant::U32(x) => x as i64,
        pdb2::Variant::U64(x) => x as i64,
        pdb2::Variant::I8(x) => x as i64,
        pdb2::Variant::I16(x) => x as i64,
        pdb2::Variant::I32(x) => x as i64,
        pdb2::Variant::I64(x) => x,
    }
}

impl SymbolStore {
    /// PDBs a type name resolves against from `dtb`, in preference order. A
    /// `module!` qualifier names the module (`nt` is the kernel); a bare name
    /// tries the kernel first, then the modules of that address space, so a
    /// name both define (`_PEB`, `_LIST_ENTRY`) gets the kernel's layout. A
    /// WOW64 process's 32-bit layouts are reached by qualifier (`ntdll32!_PEB`),
    /// and their nested types carry it (see `nested_type_prefix`).
    fn type_lookup_guids<'n>(&self, dtb: Dtb, type_name: &'n str) -> (Vec<u128>, &'n str) {
        let kernel_guid = self.kernel_guid();
        if let Some((module, name)) = type_name.rsplit_once('!') {
            let mut guids: Vec<u128> = self
                .modules
                .iter()
                .filter(|entry| {
                    self.module_in_scope(entry, dtb)
                        && entry.short_name.eq_ignore_ascii_case(module)
                })
                .map(|entry| entry.guid)
                .collect();
            if module.eq_ignore_ascii_case("nt") {
                guids.extend(kernel_guid);
            }
            guids.dedup();
            return (guids, name);
        }
        let mut guids: Vec<u128> = kernel_guid.into_iter().collect();
        guids.extend(
            self.modules
                .iter()
                .filter(|module| module.dtb == dtb && Some(module.guid) != kernel_guid)
                .map(|module| module.guid),
        );
        (guids, type_name)
    }

    pub fn find_type_across_modules(&self, dtb: Dtb, type_name: &str) -> Option<Arc<TypeInfo>> {
        let (guids, name) = self.type_lookup_guids(dtb, type_name);
        guids
            .into_iter()
            .find_map(|guid| self.dump_struct_with_types(guid, name))
    }

    /// Variants `(name, value)` of an enum, searched across the modules in the
    /// current address space (mirrors [`Self::find_type_across_modules`]).
    pub fn find_enum_across_modules(
        &self,
        dtb: Dtb,
        enum_name: &str,
    ) -> Option<Vec<(String, i64)>> {
        let (guids, name) = self.type_lookup_guids(dtb, enum_name);
        guids
            .into_iter()
            .find_map(|guid| self.enum_variants(guid, name))
    }

    /// Resolve an enum together with the PDB GUID that defines it. Hosts that
    /// cache generated enum classes need the GUID in their cache key because
    /// distinct modules may define enums with the same name.
    pub fn find_enum_def_across_modules(
        &self,
        dtb: Dtb,
        enum_name: &str,
    ) -> Option<(u128, Arc<EnumDef>)> {
        let (guids, name) = self.type_lookup_guids(dtb, enum_name);
        guids
            .into_iter()
            .find_map(|guid| self.enum_def(guid, name).map(|def| (guid, def)))
    }

    /// Error text for a name that didn't resolve as a struct/union: point at the
    /// enum tooling when it's actually an enum, else "unknown type". Keeps the
    /// hint identical across the REPL, SDK, and MCP.
    pub fn unresolved_type_message(&self, dtb: Dtb, name: &str) -> String {
        if self.find_enum_across_modules(dtb, name).is_some() {
            format!("{name} is an enum; use enum_values")
        } else {
            format!("unknown type: {name}")
        }
    }

    fn struct_size_by_name(&self, guid: u128, name: &str) -> u64 {
        self.struct_defs
            .get(&guid)
            .and_then(|defs| defs.get(name).map(|(size, _)| *size))
            .unwrap_or(0)
    }

    /// Pointer width of the PDB `guid` (see [`TypeInfo::pointer_size`]).
    pub fn pointer_size(&self, guid: u128) -> u8 {
        self.pdb_pointer_sizes.get(&guid).map_or(8, |size| *size)
    }

    /// The `module!` prefix nested type names of PDB `guid` carry so that
    /// expanding them stays in the same PDB. Only a 32-bit module's layouts
    /// need it: its `_LIST_ENTRY` or `_UNICODE_STRING` differs from the
    /// kernel's, which an unqualified lookup would otherwise prefer.
    pub(super) fn nested_type_prefix(&self, guid: u128) -> String {
        if self.pointer_size(guid) == 8 {
            return String::new();
        }
        self.modules
            .iter()
            .find(|module| module.guid == guid)
            .map(|module| format!("{}!", module.short_name))
            .unwrap_or_default()
    }

    pub(super) fn type_size<'p>(
        &self,
        guid: u128,
        finder: &pdb2::TypeFinder<'p>,
        index: pdb2::TypeIndex,
    ) -> pdb2::Result<u64> {
        let ptr_size = u64::from(self.pointer_size(guid));
        let item = finder.find(index)?;
        match item.parse()? {
            pdb2::TypeData::Primitive(data) => {
                if data.indirection.is_some() {
                    return Ok(ptr_size);
                }

                match data.kind {
                    pdb2::PrimitiveKind::Void => Ok(0),

                    pdb2::PrimitiveKind::Char
                    | pdb2::PrimitiveKind::RChar
                    | pdb2::PrimitiveKind::UChar
                    | pdb2::PrimitiveKind::I8
                    | pdb2::PrimitiveKind::U8
                    | pdb2::PrimitiveKind::Bool8 => Ok(1),

                    pdb2::PrimitiveKind::WChar
                    | pdb2::PrimitiveKind::RChar16
                    | pdb2::PrimitiveKind::Short
                    | pdb2::PrimitiveKind::UShort
                    | pdb2::PrimitiveKind::I16
                    | pdb2::PrimitiveKind::U16 => Ok(2),

                    pdb2::PrimitiveKind::Long
                    | pdb2::PrimitiveKind::ULong
                    | pdb2::PrimitiveKind::I32
                    | pdb2::PrimitiveKind::U32
                    | pdb2::PrimitiveKind::Bool32
                    | pdb2::PrimitiveKind::F32
                    | pdb2::PrimitiveKind::RChar32 => Ok(4),

                    pdb2::PrimitiveKind::Quad
                    | pdb2::PrimitiveKind::UQuad
                    | pdb2::PrimitiveKind::I64
                    | pdb2::PrimitiveKind::U64
                    | pdb2::PrimitiveKind::F64 => Ok(8),

                    pdb2::PrimitiveKind::Octa | pdb2::PrimitiveKind::UOcta => Ok(16),

                    _ => Ok(0),
                }
            }
            // Members reference their struct through a forward declaration
            // whose size is 0; the index knows the complete definition.
            pdb2::TypeData::Class(data) => Ok(if data.properties.forward_reference() {
                self.struct_size_by_name(guid, &data.name.to_string())
            } else {
                data.size
            }),
            pdb2::TypeData::Union(data) => Ok(if data.properties.forward_reference() {
                self.struct_size_by_name(guid, &data.name.to_string())
            } else {
                data.size
            }),
            pdb2::TypeData::Pointer(_) => Ok(ptr_size),
            pdb2::TypeData::Modifier(data) => self.type_size(guid, finder, data.underlying_type),
            pdb2::TypeData::Enumeration(data) => self.type_size(guid, finder, data.underlying_type),
            pdb2::TypeData::Array(data) => {
                // pdb2 reports cumulative byte sizes per dimension (`int[4][4]`
                // is `[16, 64]`), so the last entry is the whole array.
                Ok(data.dimensions.last().map_or(0, |&bytes| u64::from(bytes)))
            }
            pdb2::TypeData::Bitfield(data) => self.type_size(guid, finder, data.underlying_type),
            pdb2::TypeData::Procedure(_) => Ok(ptr_size),
            _ => Ok(0),
        }
    }

    pub(super) fn resolve_type<'p>(
        &self,
        guid: u128,
        finder: &TypeFinder<'p>,
        index: TypeIndex,
        prefix: &str,
    ) -> pdb2::Result<ParsedType> {
        let item = finder.find(index)?;
        let parsed = item.parse()?;

        match parsed {
            pdb2::TypeData::Primitive(data) => {
                let name = match data.kind {
                    PrimitiveKind::Void => "void",
                    PrimitiveKind::Char | PrimitiveKind::I8 => "CHAR",
                    PrimitiveKind::UChar | PrimitiveKind::U8 => "UCHAR",
                    PrimitiveKind::RChar => "CHAR",
                    PrimitiveKind::WChar => "WCHAR",
                    PrimitiveKind::RChar16 => "char16_t",
                    PrimitiveKind::RChar32 => "char32_t",
                    PrimitiveKind::Short | PrimitiveKind::I16 => "SHORT",
                    PrimitiveKind::UShort | PrimitiveKind::U16 => "USHORT",
                    PrimitiveKind::Long | PrimitiveKind::I32 => "LONG",
                    PrimitiveKind::ULong | PrimitiveKind::U32 => "ULONG",
                    PrimitiveKind::Quad | PrimitiveKind::I64 => "LONGLONG",
                    PrimitiveKind::UQuad | PrimitiveKind::U64 => "ULONGLONG",
                    PrimitiveKind::Octa => "INT128",
                    PrimitiveKind::UOcta => "UINT128",
                    PrimitiveKind::F32 => "float",
                    PrimitiveKind::F64 => "double",
                    PrimitiveKind::Bool8 | PrimitiveKind::Bool32 => "bool",
                    _ => "__unknown_t",
                };
                let primitive = ParsedType::Primitive(name.to_string());
                if data.indirection.is_some() {
                    Ok(ParsedType::Pointer(Box::new(primitive)))
                } else {
                    Ok(primitive)
                }
            }

            TypeData::Class(data) => Ok(ParsedType::Struct(format!("{prefix}{}", data.name))),
            TypeData::Union(data) => Ok(ParsedType::Union(format!("{prefix}{}", data.name))),
            TypeData::Enumeration(data) => Ok(ParsedType::Enum(format!("{prefix}{}", data.name))),

            TypeData::Pointer(data) => {
                let inner = self.resolve_type(guid, finder, data.underlying_type, prefix)?;
                Ok(ParsedType::Pointer(Box::new(inner)))
            }

            TypeData::Array(data) => {
                let inner = self.resolve_type(guid, finder, data.element_type, prefix)?;
                // Total byte size (see `type_size`) over the element size gives
                // the flattened element count.
                let bytes = data.dimensions.last().copied().unwrap_or(0);
                let sizeof_type = (self.type_size(guid, finder, data.element_type)? as u32).max(1);
                Ok(ParsedType::Array(Box::new(inner), bytes / sizeof_type))
            }

            TypeData::Modifier(data) => {
                self.resolve_type(guid, finder, data.underlying_type, prefix)
            }
            TypeData::Bitfield(data) => {
                let inner = self.resolve_type(guid, finder, data.underlying_type, prefix)?;

                Ok(ParsedType::Bitfield {
                    underlying: Box::new(inner),
                    pos: data.position,
                    len: data.length,
                })
            }

            pdb2::TypeData::Procedure(data) => {
                let return_type = if let Some(idx) = data.return_type {
                    self.resolve_type(guid, finder, idx, prefix)?
                } else {
                    ParsedType::Primitive("void".to_string())
                };

                let mut args = Vec::new();
                if let Ok(arg_item) = finder.find(data.argument_list)
                    && let Ok(pdb2::TypeData::ArgumentList(list)) = arg_item.parse()
                {
                    for arg_idx in list.arguments {
                        let arg_type = self.resolve_type(guid, finder, arg_idx, prefix)?;
                        args.push(arg_type);
                    }
                }

                Ok(ParsedType::Function(Box::new(return_type), args))
            }

            _ => Ok(ParsedType::Unknown),
        }
    }

    fn process_field_list<'p>(
        &self,
        guid: u128,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        prefix: &str,
        fields_map: &mut HashMap<String, FieldInfo>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;

        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Member(member) = field {
                    let name = member.name.to_string().into_owned();
                    let offset = member.offset;

                    let type_info =
                        self.resolve_type(guid, type_finder, member.field_type, prefix)?;

                    fields_map.insert(
                        name,
                        FieldInfo {
                            offset: offset as u32,
                            size: self.type_size(guid, type_finder, member.field_type)?,
                            type_data: type_info,
                        },
                    );
                }
            }

            if let Some(more_fields) = list.continuation {
                self.process_field_list(guid, type_finder, more_fields, prefix, fields_map)?;
            }
        }
        Ok(())
    }

    pub fn dump_struct_with_types<S>(&self, guid: u128, struct_name: S) -> Option<Arc<TypeInfo>>
    where
        S: Into<String> + AsRef<str>,
    {
        let cache_key = (guid, struct_name.as_ref().to_string());
        if let Some(cached) = self.type_cache.get(&cache_key) {
            return cached.clone();
        }

        let definition = self
            .struct_defs
            .get(&guid)
            .and_then(|defs| defs.get(struct_name.as_ref()).copied());
        let Some((size, field_index)) = definition else {
            self.type_cache.insert(cache_key, None);
            return None;
        };

        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        // The finder only knows records the iterator has passed. A field list
        // and everything it references precede the class record, so stop once
        // the list is indexed; fall back to the full stream if a member still
        // resolves to an unindexed record.
        while type_finder.max_index() < field_index {
            let Some(_) = iter.next().ok()? else { break };
            type_finder.update(&iter);
        }
        let mut fields = HashMap::new();
        let prefix = self.nested_type_prefix(guid);
        let parsed =
            match self.process_field_list(guid, &type_finder, field_index, &prefix, &mut fields) {
                Err(pdb2::Error::TypeNotIndexed(..)) => {
                    while iter.next().ok()?.is_some() {
                        type_finder.update(&iter);
                    }
                    fields.clear();
                    self.process_field_list(guid, &type_finder, field_index, &prefix, &mut fields)
                }
                other => other,
            };
        if parsed.is_err() {
            self.type_cache.insert(cache_key, None);
            return None;
        }

        let type_info = Arc::new(TypeInfo {
            name: struct_name.into(),
            size: size as usize,
            fields,
            pointer_size: self.pointer_size(guid),
        });
        self.type_cache
            .insert(cache_key, Some(Arc::clone(&type_info)));
        Some(type_info)
    }

    /// Variants `(name, value)` of a PDB enum, in declaration order. Lets
    /// callers map a raw enum value (e.g. an `_MI_SYSTEM_VA_TYPE` region tag)
    /// back to its name.
    pub fn enum_variants(&self, guid: u128, enum_name: &str) -> Option<Vec<(String, i64)>> {
        self.enum_def(guid, enum_name)
            .map(|def| def.variants.clone())
    }

    /// A PDB enum's variants and storage width. Enums live in the type stream
    /// but aren't in the (class-only) type index, so the first lookup scans
    /// like `dump_struct_with_types`; the result (a miss too) is cached per
    /// guid, which is what makes reading enum-typed fields cheap.
    pub fn enum_def(&self, guid: u128, enum_name: &str) -> Option<Arc<EnumDef>> {
        let cache_key = (guid, enum_name.to_string());
        if let Some(cached) = self.enum_cache.get(&cache_key) {
            return cached.clone();
        }
        let def = self.scan_enum(guid, enum_name).map(Arc::new);
        self.enum_cache.insert(cache_key, def.clone());
        def
    }

    fn scan_enum(&self, guid: u128, enum_name: &str) -> Option<EnumDef> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Enumeration(en)) = typ.parse()
                && en.name.to_string() == enum_name
                && !en.properties.forward_reference()
            {
                let mut variants = Vec::new();
                self.collect_enum_variants(&type_finder, en.fields, &mut variants)
                    .ok()?;
                let size = self.type_size(guid, &type_finder, en.underlying_type).ok();
                return Some(EnumDef { variants, size });
            }
        }
        None
    }

    fn collect_enum_variants<'p>(
        &self,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        out: &mut Vec<(String, i64)>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;
        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Enumerate(e) = field {
                    out.push((e.name.to_string().into_owned(), variant_to_i64(&e.value)));
                }
            }
            if let Some(more) = list.continuation {
                self.collect_enum_variants(type_finder, more, out)?;
            }
        }
        Ok(())
    }
}
