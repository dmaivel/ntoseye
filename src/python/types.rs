//! Address-space-bound PDB type metadata and reflective struct cursors.

use std::collections::BTreeSet;
use std::sync::Arc;

use indexmap::IndexMap;

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyAttributeError, PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};

use super::context::Space;
use super::handle::Owner;
use super::record::PlainDict;
use super::symbols::load_scope_symbols;
use super::{err, raise};
use crate::backend::MemoryOps;
use crate::error::Result as CoreResult;
use crate::layout::{
    EnumDef, FieldInfo, FieldValue, ParsedType, TypeInfo, bitfield_mask, le_uint, named_type,
    unqualified_type_name,
};
use crate::symbols::SymbolStore;
use crate::target::{CODE_BITNESS_AMD64, CODE_BITNESS_X86};
use crate::types::{Dtb, VirtAddr};

fn lookup_field<'a>(
    info: &'a TypeInfo,
    type_name: &str,
    field_name: &str,
) -> PyResult<&'a FieldInfo> {
    info.fields
        .get(field_name)
        .ok_or_else(|| raise(format!("{type_name} has no field '{field_name}'")))
}

fn pointer_width(name: &str, width: u64) -> PyResult<usize> {
    let width = usize::try_from(width)
        .map_err(|_| raise(format!("field '{name}' has invalid pointer width")))?;
    if !(1..=8).contains(&width) {
        return Err(raise(format!(
            "field '{name}' has invalid pointer width {width}"
        )));
    }
    Ok(width)
}

/// PDB types scoped to an address space: `dbg.types`, `proc.types`.
#[pyclass(module = "ntoseye")]
pub struct Types {
    pub owner: Owner,
    pub space: Space,
}

impl Types {
    pub fn new(owner: Owner, space: Space) -> Types {
        Types { owner, space }
    }

    /// Resolve `name` in this space: `Err` carries the miss message.
    fn lookup(&self, py: Python<'_>, name: &str) -> PyResult<Result<Type, String>> {
        let found = self.owner.with_in(py, &self.space.context(), |session| {
            load_scope_symbols(session, &self.space)?;
            let dtb = session.target.current_dtb();
            let symbols = &session.target.symbols;
            Ok(
                if let Some(info) = symbols.find_type_across_modules(dtb, name) {
                    Ok(Definition::Layout(info))
                } else if let Some((_, def)) = symbols.find_enum_def_across_modules(dtb, name) {
                    Ok(Definition::Enum(def))
                } else {
                    Err(format!("unknown type: {name}"))
                },
            )
        })?;
        Ok(found.map(|definition| Type {
            owner: self.owner.clone_ref(py),
            space: self.space.clone(),
            name: name.to_string(),
            definition,
        }))
    }
}

/// What a PDB type name resolved to.
enum Definition {
    /// A struct or union layout.
    Layout(Arc<TypeInfo>),
    Enum(Arc<EnumDef>),
}

#[pymethods]
impl Types {
    /// Resolve a struct, union, or enum by PDB name; unknown names raise `KeyError`.
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<Type> {
        self.lookup(py, name)?.map_err(PyKeyError::new_err)
    }

    /// Return the named type, or `None` when it does not resolve.
    fn get(&self, py: Python<'_>, name: &str) -> PyResult<Option<Type>> {
        Ok(self.lookup(py, name)?.ok())
    }

    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(name) = key.extract::<String>() else {
            return Ok(false);
        };
        Ok(self.lookup(py, &name)?.is_ok())
    }

    fn __repr__(&self) -> String {
        let space = match &self.space {
            Space::Kernel => "kernel",
            Space::Process(_) => "process",
            Space::Physical => "physical",
        };
        format!("<Types space={space}>")
    }
}

/// A PDB field layout: name, byte offset, byte size, and type spelling.
#[pyclass(frozen, get_all, module = "ntoseye")]
pub struct Field {
    /// The field name.
    name: String,
    /// Byte offset within the containing type.
    offset: u64,
    /// Size in bytes.
    size: u64,
    #[pyo3(name = "type")]
    /// The PDB type spelling.
    type_name: String,
}

impl Field {
    fn new(name: String, info: &FieldInfo) -> Field {
        Field {
            name,
            offset: u64::from(info.offset),
            size: info.size,
            type_name: info.type_data.to_string(),
        }
    }
}

#[pymethods]
impl Field {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("name", &self.name)?;
        dict.set_item("offset", self.offset)?;
        dict.set_item("size", self.size)?;
        dict.set_item("type", &self.type_name)?;
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        format!(
            "<Field {} offset={:#x} size={:#x} type={:?}>",
            self.name, self.offset, self.size, self.type_name
        )
    }
}

/// A named PDB struct/union layout or enum definition.
#[pyclass(module = "ntoseye")]
pub struct Type {
    owner: Owner,
    space: Space,
    name: String,
    definition: Definition,
}

impl Type {
    fn layout(owner: Owner, space: Space, name: String, info: Arc<TypeInfo>) -> Type {
        Type {
            owner,
            space,
            name,
            definition: Definition::Layout(info),
        }
    }

    fn struct_info(&self) -> PyResult<&Arc<TypeInfo>> {
        match &self.definition {
            Definition::Layout(info) => Ok(info),
            Definition::Enum(_) => Err(raise(format!(
                "{} is an enum and has no struct layout",
                self.name
            ))),
        }
    }

    /// The fields by name, in offset order.
    fn field_map(&self) -> IndexMap<String, Field> {
        let Definition::Layout(info) = &self.definition else {
            return IndexMap::new();
        };
        info.fields_in_order()
            .into_iter()
            .map(|(name, field)| (name.clone(), Field::new(name.clone(), field)))
            .collect()
    }
}

#[pymethods]
impl Type {
    /// PDB type name (for example, `_EPROCESS`).
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    /// Size in bytes, including the underlying storage width for enums.
    #[getter]
    fn size(&self) -> u64 {
        match &self.definition {
            Definition::Layout(info) => info.size as u64,
            Definition::Enum(def) => def.size.unwrap_or(0),
        }
    }

    /// Field layouts by name, in offset order. Enums have no fields.
    #[getter]
    fn fields(&self) -> IndexMap<String, Field> {
        self.field_map()
    }

    /// Enum members by name, in declaration order; raises for structs and
    /// unions.
    #[getter]
    fn values(&self) -> PyResult<IndexMap<String, i64>> {
        match &self.definition {
            Definition::Enum(def) => Ok(def.variants.iter().cloned().collect()),
            Definition::Layout(_) => Err(raise(format!("{} is not an enum", self.name))),
        }
    }

    /// Bind this layout to an address as a reflective struct cursor.
    fn at(&self, py: Python<'_>, addr: u64) -> PyResult<Struct> {
        self.struct_info()?;
        Struct::new(py, &self.owner, self.space.clone(), &self.name, addr)
    }

    /// Walk an intrusive list whose head is at `head` and whose links are `link_field`.
    fn walk(&self, py: Python<'_>, head: u64, link_field: &str) -> PyResult<Vec<Struct>> {
        self.struct_info()?;
        let addresses =
            list_record_addresses(py, &self.owner, &self.space, head, &self.name, link_field)?;
        addresses
            .into_iter()
            .map(|addr| Struct::new(py, &self.owner, self.space.clone(), &self.name, addr))
            .collect()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("name", &self.name)?;
        dict.set_item("size", self.size())?;
        let fields = PyDict::new(py);
        for (name, field) in self.field_map() {
            fields.set_item(name, field.to_dict(py)?)?;
        }
        dict.set_item("fields", fields)?;
        if let Definition::Enum(def) = &self.definition {
            dict.set_item(
                "values",
                def.variants.iter().cloned().collect::<IndexMap<_, _>>(),
            )?;
        }
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        match &self.definition {
            Definition::Enum(_) => format!("<Type {} enum>", self.name),
            Definition::Layout(_) => format!("<Type {} size={:#x}>", self.name, self.size()),
        }
    }
}

/// `cursor[key]`: a field by name, or a sibling cursor by index
/// (`((T*)p)[i]`).
#[derive(FromPyObject)]
pub enum StructKey {
    Field(String),
    Index(i64),
}

/// A PDB type bound to an address in an address space: a reflective cursor.
#[pyclass(module = "ntoseye")]
pub struct Struct {
    owner: Owner,
    space: Space,
    dtb: u64,
    name: String,
    info: Arc<TypeInfo>,
    addr: u64,
}

impl Struct {
    /// Resolve `type_name` in `space` and bind it at `addr`.
    pub fn new(
        py: Python<'_>,
        owner: &Owner,
        space: Space,
        type_name: &str,
        addr: u64,
    ) -> PyResult<Struct> {
        let owner = owner.derive(py);
        let (dtb, info) = resolve_layout(py, &owner, &space, type_name)?;
        Ok(Struct {
            owner,
            space,
            dtb,
            name: type_name.to_string(),
            info,
            addr,
        })
    }

    fn with_layout(
        py: Python<'_>,
        owner: &Owner,
        space: Space,
        dtb: u64,
        name: String,
        info: Arc<TypeInfo>,
        addr: u64,
    ) -> Struct {
        Struct {
            owner: owner.derive(py),
            space,
            dtb,
            name,
            info,
            addr,
        }
    }

    fn field_address(&self, field: &FieldInfo) -> u64 {
        self.addr.wrapping_add(u64::from(field.offset))
    }

    fn get_field(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let field = lookup_field(&self.info, &self.name, name)?;
        let addr = self.field_address(field);

        if named_type(&field.type_data, "_UNICODE_STRING") {
            // The enclosing layout's width is the field's: an `ntdll32!`
            // struct embeds the 32-bit descriptor.
            let bits = if self.info.pointer_size == 4 {
                CODE_BITNESS_X86
            } else {
                CODE_BITNESS_AMD64
            };
            let result = self.owner.with_in(py, &self.space.context(), |session| {
                Ok(session.target.read_unicode_string(VirtAddr(addr), bits))
            })?;
            return result
                .map_err(err)?
                .into_bound_py_any(py)
                .map(|value| value.unbind());
        }

        if let ParsedType::Struct(type_name) | ParsedType::Union(type_name) = &field.type_data {
            return Ok(Py::new(
                py,
                Struct::new(py, &self.owner, self.space.clone(), type_name, addr)?,
            )?
            .into_any());
        }

        if let ParsedType::Array(element, count) = &field.type_data
            && field.type_data.c_string_len().is_none()
            && *count > 0
        {
            return self.array_field(py, element, *count, addr, field.size);
        }

        let size = usize::try_from(field.size)
            .map_err(|_| raise(format!("field '{name}' has invalid byte width")))?;
        if size == 0 {
            return Err(raise(format!("field '{name}' has no byte size")));
        }
        let read = self.owner.with_in(py, &self.space.context(), |session| {
            let mut bytes = vec![0; size];
            Ok(session
                .read_masked(VirtAddr(addr), &mut bytes)
                .map(|()| bytes))
        })?;
        let bytes = read.map_err(err)?;

        let result = match &field.type_data {
            ParsedType::Bitfield { .. } | ParsedType::Pointer(_) => {
                field.decode(le_uint(&bytes)).into_bound_py_any(py)?
            }
            ParsedType::Enum(enum_name) if matches!(size, 1 | 2 | 4 | 8) => {
                return enum_value(py, &self.owner, &self.space, enum_name, le_uint(&bytes));
            }
            ParsedType::Array(_, _) if field.type_data.c_string_len().is_some() => {
                SymbolStore::read_c_string_lossy(&bytes).into_bound_py_any(py)?
            }
            _ => match size {
                1 | 2 | 4 | 8 => le_uint(&bytes).into_bound_py_any(py)?,
                _ => PyBytes::new(py, &bytes).into_any(),
            },
        };
        Ok(result.unbind())
    }

    fn array_field(
        &self,
        py: Python<'_>,
        element: &ParsedType,
        count: u32,
        addr: u64,
        total_size: u64,
    ) -> PyResult<Py<PyAny>> {
        let count = usize::try_from(count)
            .map_err(|_| raise("array element count does not fit this host"))?;
        if count == 0 {
            return Ok(PyList::empty(py).into_any().unbind());
        }

        if let ParsedType::Struct(type_name) | ParsedType::Union(type_name) = element {
            let (dtb, info) = resolve_layout(py, &self.owner, &self.space, type_name)?;
            let mut stride = usize::try_from(total_size / count as u64)
                .map_err(|_| raise("array element size does not fit this host"))?;
            if stride == 0 {
                stride = info.size;
            }
            if stride == 0 {
                return Err(raise(format!(
                    "array field at {addr:#x} has zero-sized elements"
                )));
            }
            let list = PyList::empty(py);
            for index in 0..count {
                let element_addr = addr.wrapping_add(index.wrapping_mul(stride) as u64);
                let item = Struct::with_layout(
                    py,
                    &self.owner,
                    self.space.clone(),
                    dtb,
                    type_name.clone(),
                    Arc::clone(&info),
                    element_addr,
                );
                list.append(Py::new(py, item)?)?;
            }
            return Ok(list.into_any().unbind());
        }

        let stride = usize::try_from(total_size / count as u64)
            .map_err(|_| raise("array element size does not fit this host"))?;
        if stride == 0 {
            return Err(raise(format!(
                "array field at {addr:#x} has zero-sized elements"
            )));
        }
        let length = stride
            .checked_mul(count)
            .ok_or_else(|| raise("array field size overflows this host"))?;
        let read = self.owner.with_in(py, &self.space.context(), |session| {
            let mut bytes = vec![0; length];
            Ok(session
                .read_masked(VirtAddr(addr), &mut bytes)
                .map(|()| bytes))
        })?;
        let bytes = read.map_err(err)?;
        let list = PyList::empty(py);
        let scalar = matches!(element, ParsedType::Pointer(_)) || matches!(stride, 1 | 2 | 4 | 8);
        for chunk in bytes.chunks_exact(stride) {
            if let ParsedType::Enum(enum_name) = element
                && scalar
            {
                list.append(enum_value(
                    py,
                    &self.owner,
                    &self.space,
                    enum_name,
                    le_uint(chunk),
                )?)?;
            } else if scalar {
                list.append(le_uint(chunk))?;
            } else {
                list.append(PyBytes::new(py, chunk))?;
            }
        }
        Ok(list.into_any().unbind())
    }

    fn set_field(&self, py: Python<'_>, name: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let field = lookup_field(&self.info, &self.name, name)?;
        let addr = self.field_address(field);

        if matches!(
            &field.type_data,
            ParsedType::Struct(_) | ParsedType::Union(_)
        ) {
            return Err(raise(format!(
                "cannot assign to nested struct field '{name}'; assign its scalar fields instead"
            )));
        }

        if let ParsedType::Bitfield { pos, len, .. } = &field.type_data {
            let integer = value
                .extract::<u64>()
                .map_err(|_| raise(format!("field '{name}' is a bitfield; expected int")))?;
            let mask = bitfield_mask(*len);
            let pos = u32::from(*pos);
            let size = ((pos + u32::from(*len)).div_ceil(8).clamp(1, 8)) as usize;
            let write = self.owner.with_in(py, &self.space.context(), |session| {
                let memory = session.target.context_memory();
                let mut bytes = vec![0; size];
                Ok(memory
                    .read_bytes(VirtAddr(addr), &mut bytes)
                    .and_then(|()| {
                        let raw = (le_uint(&bytes) & !(mask << pos)) | ((integer & mask) << pos);
                        bytes.copy_from_slice(&raw.to_le_bytes()[..size]);
                        memory.write_bytes(VirtAddr(addr), &bytes)
                    }))
            })?;
            return write.map_err(err);
        }

        if matches!(&field.type_data, ParsedType::Pointer(_)) {
            let integer = value
                .extract::<u64>()
                .map_err(|_| raise(format!("field '{name}' is a pointer; expected int")))?;
            let size = pointer_width(name, field.size)?;
            let bytes = integer.to_le_bytes();
            let write = self.owner.with_in(py, &self.space.context(), |session| {
                Ok(session
                    .target
                    .context_memory()
                    .write_bytes(VirtAddr(addr), &bytes[..size]))
            })?;
            return write.map_err(err);
        }

        let size = usize::try_from(field.size)
            .map_err(|_| raise(format!("field '{name}' has invalid byte width")))?;
        let bytes = if matches!(size, 1 | 2 | 4 | 8)
            && let Ok(integer) = value.extract::<u64>()
        {
            integer.to_le_bytes()[..size].to_vec()
        } else {
            let bytes = value.extract::<Vec<u8>>().map_err(|_| {
                raise(format!(
                    "field '{name}' ({size} bytes): expected int or bytes"
                ))
            })?;
            if bytes.len() != size {
                return Err(raise(format!(
                    "field '{name}' is {size} bytes; got {} bytes",
                    bytes.len()
                )));
            }
            bytes
        };
        let write = self.owner.with_in(py, &self.space.context(), |session| {
            Ok(session
                .target
                .context_memory()
                .write_bytes(VirtAddr(addr), &bytes))
        })?;
        write.map_err(err)
    }

    fn read_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let info = Arc::clone(&self.info);
        let addr = self.addr;
        let read = self.owner.with_in(py, &self.space.context(), |session| {
            let mut bytes = vec![0; info.size];
            Ok(session
                .read_masked(VirtAddr(addr), &mut bytes)
                .map(|()| info.decode_fields(&bytes)))
        })?;
        let values = read.map_err(err)?;
        let dict = PyDict::new(py);
        for (name, value) in values {
            let enum_name = self.info.fields.get(&name).and_then(|field| {
                if let ParsedType::Enum(enum_name) = &field.type_data {
                    Some(enum_name.as_str())
                } else {
                    None
                }
            });
            match value {
                FieldValue::Int(number) if let Some(enum_name) = enum_name => {
                    dict.set_item(
                        name,
                        enum_value(py, &self.owner, &self.space, enum_name, number)?,
                    )?;
                }
                FieldValue::Int(number)
                | FieldValue::Pointer(number)
                | FieldValue::Bitfield(number) => dict.set_item(name, number)?,
                FieldValue::Bytes(bytes) => dict.set_item(name, PyBytes::new(py, &bytes))?,
            }
        }
        Ok(dict)
    }
}

#[pymethods]
impl Struct {
    /// Address this cursor refers to.
    #[getter]
    fn addr(&self) -> u64 {
        self.addr
    }

    /// The PDB type of this cursor.
    #[getter]
    fn r#type(&self, py: Python<'_>) -> Type {
        Type::layout(
            self.owner.clone_ref(py),
            self.space.clone(),
            self.name.clone(),
            Arc::clone(&self.info),
        )
    }

    /// Reinterpret this address as another PDB type.
    fn cast(&self, py: Python<'_>, type_name: &str) -> PyResult<Struct> {
        Struct::new(py, &self.owner, self.space.clone(), type_name, self.addr)
    }

    /// The address of field `name`, as C's `&cursor->name`: what a watchpoint
    /// or a raw read needs. A bitfield's address is its storage unit's.
    fn address_of(&self, name: &str) -> PyResult<u64> {
        Ok(self.field_address(lookup_field(&self.info, &self.name, name)?))
    }

    /// Follow a pointer field to its typed target.
    fn follow(&self, py: Python<'_>, name: &str) -> PyResult<Struct> {
        let field = lookup_field(&self.info, &self.name, name)?;
        let type_name = match &field.type_data {
            ParsedType::Pointer(inner) => match inner.as_ref() {
                ParsedType::Struct(name) | ParsedType::Union(name) => name.clone(),
                _ => {
                    return Err(raise(format!(
                        "field '{name}' is not a pointer to a struct"
                    )));
                }
            },
            _ => return Err(raise(format!("field '{name}' is not a pointer"))),
        };
        let size = pointer_width(name, field.size)?;
        let addr = self.field_address(field);
        let read = self.owner.with_in(py, &self.space.context(), |session| {
            let mut bytes = vec![0; size];
            Ok(session
                .read_masked(VirtAddr(addr), &mut bytes)
                .map(|()| le_uint(&bytes)))
        })?;
        let target = read.map_err(err)?;
        Struct::new(py, &self.owner, self.space.clone(), &type_name, target)
    }

    /// Walk a list whose head is a field of this cursor.
    fn walk(
        &self,
        py: Python<'_>,
        head_field: &str,
        record_type: &str,
        link_field: &str,
    ) -> PyResult<Vec<Struct>> {
        let field = lookup_field(&self.info, &self.name, head_field)?;
        let head = self.field_address(field);
        let addresses =
            list_record_addresses(py, &self.owner, &self.space, head, record_type, link_field)?;
        addresses
            .into_iter()
            .map(|addr| Struct::new(py, &self.owner, self.space.clone(), record_type, addr))
            .collect()
    }

    /// Read one whole-struct snapshot into a dictionary; nested struct fields are omitted.
    fn read<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.read_dict(py).map(PlainDict)
    }

    /// The field value, or an integer sibling cursor index (`((T*)p)[i]`).
    fn __getitem__(&self, py: Python<'_>, key: StructKey) -> PyResult<Py<PyAny>> {
        let name = match key {
            StructKey::Field(name) => name,
            StructKey::Index(index) => {
                self.owner.check(py)?;
                if self.info.size == 0 {
                    return Err(raise(format!("{} has no size to index by", self.name)));
                }
                let addr = self
                    .addr
                    .wrapping_add((index as u64).wrapping_mul(self.info.size as u64));
                let sibling = Struct::with_layout(
                    py,
                    &self.owner,
                    self.space.clone(),
                    self.dtb,
                    self.name.clone(),
                    Arc::clone(&self.info),
                    addr,
                );
                return Ok(Py::new(py, sibling)?.into_any());
            }
        };
        if !self.info.fields.contains_key(&name) {
            return Err(PyKeyError::new_err(name));
        }
        self.get_field(py, &name)
    }

    /// Write a PDB field by name.
    fn __setitem__(&self, py: Python<'_>, name: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        if !self.info.fields.contains_key(&name) {
            return Err(PyKeyError::new_err(name));
        }
        self.set_field(py, &name, value)
    }

    /// PDB fields and the cursor's public members, for tab completion.
    fn __dir__(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = self.info.fields.keys().cloned().collect();
        names.extend(
            [
                "addr",
                "address_of",
                "type",
                "cast",
                "follow",
                "walk",
                "read",
                "to_dict",
            ]
            .into_iter()
            .map(str::to_string),
        );
        names.into_iter().collect()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.read_dict(py).map(PlainDict)
    }

    fn __repr__(&self) -> String {
        format!("<{} @ {:#x}>", self.name, self.addr)
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Struct>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner)
                && self.addr == other.addr
                && self.name == other.name
                && self.dtb == other.dtb
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash((self.addr, &self.name, self.dtb))
    }

    /// Reflective field access; missing fields raise `AttributeError`.
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        if name.starts_with("__") || !self.info.fields.contains_key(name) {
            return Err(PyAttributeError::new_err(format!(
                "'{}' has no field '{}'",
                self.name, name
            )));
        }
        self.get_field(py, name)
    }

    /// `cursor.Field = value`; only actual PDB fields are assignable.
    fn __setattr__(&self, py: Python<'_>, name: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        if !self.info.fields.contains_key(name) {
            return Err(PyAttributeError::new_err(format!(
                "'{}' has no settable field '{}'",
                self.name, name
            )));
        }
        self.set_field(py, name, value)
    }
}

/// The struct/union layout `type_name` names in `space`, with the space's
/// DTB; a miss raises with the symbol store's hint (e.g. "is an enum").
fn resolve_layout(
    py: Python<'_>,
    owner: &Owner,
    space: &Space,
    type_name: &str,
) -> PyResult<(Dtb, Arc<TypeInfo>)> {
    owner.with_in(py, &space.context(), |session| {
        let dtb = session.target.current_dtb();
        let symbols = &session.target.symbols;
        symbols
            .find_type_across_modules(dtb, type_name)
            .map(|info| (dtb, info))
            .ok_or_else(|| raise(symbols.unresolved_type_message(dtb, type_name)))
    })
}

fn list_record_addresses(
    py: Python<'_>,
    owner: &Owner,
    space: &Space,
    head: u64,
    record_type: &str,
    link_field: &str,
) -> PyResult<Vec<u64>> {
    let scoped = owner.with_in(py, &space.context(), |session| {
        let dtb = session.target.current_dtb();
        let addresses = session
            .target
            .types_in(dtb)
            .list_at(VirtAddr(head), record_type, link_field)
            .and_then(|records| {
                records
                    .map(|record| record.map(|record| record.addr().0))
                    .collect::<CoreResult<Vec<_>>>()
            });
        Ok(addresses)
    })?;
    scoped.map_err(err)
}

/// `value` as a member of PDB enum `enum_name`, or as a plain integer when the
/// type or value is not defined. Generated `IntEnum` classes are cached by PDB GUID.
pub fn enum_value(
    py: Python<'_>,
    owner: &Owner,
    space: &Space,
    enum_name: &str,
    value: u64,
) -> PyResult<Py<PyAny>> {
    let resolved = owner.with_in(py, &space.context(), |session| {
        let dtb = session.target.current_dtb();
        Ok(session
            .target
            .symbols
            .find_enum_def_across_modules(dtb, enum_name))
    })?;
    let Some((guid, def)) = resolved else {
        return Ok(value.into_bound_py_any(py)?.unbind());
    };

    static ENUM_CLASSES: PyOnceLock<Py<PyDict>> = PyOnceLock::new();
    let cache =
        ENUM_CLASSES.get_or_try_init(py, || Ok::<Py<PyDict>, PyErr>(PyDict::new(py).unbind()))?;
    let short_name = unqualified_type_name(enum_name);
    let key = format!("{guid:032x}!{short_name}");
    let class = if let Some(class) = cache.bind(py).get_item(&key)? {
        class
    } else {
        let members = PyDict::new(py);
        for (name, variant) in &def.variants {
            members.set_item(name, variant)?;
        }
        let class = py
            .import("enum")?
            .getattr("IntEnum")?
            .call1((short_name, members))?;
        cache.bind(py).set_item(&key, &class)?;
        class
    };

    // A signed underlying type stores negative members in two's complement
    // of its width; read the raw bits back as that signed value.
    let member = match def.size {
        Some(width @ (1 | 2 | 4)) => {
            let shift = 64 - 8 * width as u32;
            ((value << shift) as i64) >> shift
        }
        _ => value as i64,
    };
    for candidate in [value as i64, member] {
        match class.call1((candidate,)) {
            Ok(member) => return Ok(member.unbind()),
            Err(error) if error.is_instance_of::<PyValueError>(py) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(value.into_bound_py_any(py)?.unbind())
}
