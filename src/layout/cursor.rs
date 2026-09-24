use std::sync::Arc;

use zerocopy::{FromBytes, IntoBytes};

use super::{FieldInfo, ParsedType, TypeInfo, le_uint};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::memory::AddressSpace;
use crate::phys::PhysMem;
use crate::symbols::SymbolStore;
use crate::target::ListCursor;
use crate::types::{Arch, Dtb, VirtAddr};

/// A module's struct/type namespace bound to a read address space: the entry
/// point for layout lookups and fluent cursors. Cheap to copy. The namespace
/// (`guid`) and the space (`dtb`) are independent, so kernel types read
/// through any process's page tables.
#[derive(Clone, Copy)]
pub struct Types<'a> {
    symbols: &'a SymbolStore,
    /// Module whose PDB answers unqualified names; `None` resolves only
    /// `module!`-qualified names (a target without a discovered kernel).
    guid: Option<u128>,
    phys: &'a Arc<PhysMem>,
    arch: Arch,
    kernel_dtb: Dtb,
    dtb: Dtb,
}

impl<'a> Types<'a> {
    /// The namespace of module `guid` (see [`Image::types_in`](crate::guest::Image::types_in)) without an
    /// image object: how a target with no discovered kernel still reaches
    /// qualified types in its identity-mapped memory.
    pub fn new(
        symbols: &'a SymbolStore,
        guid: Option<u128>,
        phys: &'a Arc<PhysMem>,
        arch: Arch,
        kernel_dtb: Dtb,
        dtb: Dtb,
    ) -> Self {
        Self {
            symbols,
            guid,
            phys,
            arch,
            kernel_dtb,
            dtb,
        }
    }

    fn memory(self) -> AddressSpace<'a, Arc<PhysMem>> {
        AddressSpace::for_arch(self.phys, self.dtb, self.kernel_dtb, self.arch)
    }

    /// The parsed layout of struct `name` from the object's PDB (cached). A
    /// `module!`-qualified name resolves in this space's modules instead,
    /// which is how a 32-bit layout (`ntdll32!_PEB`) and the nested types it
    /// names are reached.
    pub fn layout<S>(self, name: S) -> Result<Arc<TypeInfo>>
    where
        S: Into<String> + AsRef<str>,
    {
        if name.as_ref().contains('!') {
            return self
                .symbols
                .find_type_across_modules(self.dtb, name.as_ref())
                .ok_or_else(|| Error::StructNotFound(name.into()));
        }
        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        self.symbols
            .dump_struct_with_types(guid, name.as_ref())
            .ok_or_else(|| Error::StructNotFound(name.into()))
    }

    /// Open a struct cursor at `base` in this space. The layout `name` resolves
    /// against the object's PDB; reads come from this space's `dtb`.
    pub fn struct_at(self, name: &str, base: VirtAddr) -> Result<StructRef<'a>> {
        let ti = self.layout(name)?;
        Ok(self.struct_with_layout(ti, base))
    }

    /// Open a struct cursor with an already-resolved layout in this address
    /// space. Callers that cache layouts can avoid repeating the type lookup.
    pub fn struct_with_layout(self, layout: Arc<TypeInfo>, base: VirtAddr) -> StructRef<'a> {
        StructRef {
            types: self,
            ti: layout,
            base,
            image: None,
        }
    }

    /// Walk an intrusive `_LIST_ENTRY` starting at a bare head address (e.g. a
    /// list-head symbol like `PsLoadedModuleList`), yielding a cursor per
    /// record. `record_type`/`link_field` give the record layout and the
    /// embedded link (`CONTAINING_RECORD`). Iteration is bounded and stops on a
    /// cycle. Shared by [`StructRef::list`], which sources `head` from a field.
    ///
    /// Each record is prefetched (see [`StructRef::prefetch`]) so its fields
    /// and the link to the next record come from one read.
    pub fn list_at(
        self,
        head: VirtAddr,
        record_type: &str,
        link_field: &str,
    ) -> Result<impl Iterator<Item = Result<StructRef<'a>>> + 'a> {
        let record_ti = self.layout(record_type)?;
        let link_offset = record_ti.field_offset(link_field)?;

        const MAX: usize = 1000;
        let pointer_size = usize::from(record_ti.pointer_size);
        let read_link = move |memory: &dyn Fn(&mut [u8]) -> Result<()>| -> Result<VirtAddr> {
            let mut bytes = [0u8; 8];
            memory(&mut bytes[..pointer_size])?;
            Ok(VirtAddr(le_uint(&bytes[..pointer_size])))
        };
        let initial = read_link(&|buf| self.memory().read_bytes(head, buf))?;
        let mut cursor = ListCursor::new(head, MAX);
        cursor.advance(Ok(initial));

        Ok(std::iter::from_fn(move || {
            let current = cursor.take_current()?;

            let record = self
                .struct_with_layout(
                    Arc::clone(&record_ti),
                    VirtAddr(current.0.wrapping_sub(link_offset)),
                )
                .prefetch();

            // Flink sits at offset 0 of the link's _LIST_ENTRY
            match read_link(&|buf| record.read_bytes_at(link_offset, buf)) {
                Ok(next) => cursor.advance(Ok(next)),
                Err(e) => {
                    cursor.advance(Err(e.to_string()));
                    return Some(Err(e));
                }
            }
            Some(Ok(record))
        }))
    }
}

/// A fluent cursor over a struct instance in guest memory: a resolved layout
/// (`ti`) sitting at `base` in the `dtb` address space, plus the symbol context
/// to resolve the types of fields you walk into. This is to structs what
/// [`SymbolRef`](crate::guest::SymbolRef) is to symbols: `follow`/`read_field`/`list` chain off it, and
/// the type cache makes each step's layout lookup cheap.
pub struct StructRef<'a> {
    /// Namespace for the types of fields walked into, and the space read.
    types: Types<'a>,
    ti: Arc<TypeInfo>,
    base: VirtAddr,
    /// Prefetched copy of the struct's bytes from `base`; field reads inside
    /// it cost no memory request.
    image: Option<Arc<[u8]>>,
}

/// Largest struct [`StructRef::prefetch`] copies whole. Loader entries,
/// `_EPROCESS`, and `_ETHREAD` all fit; anything bigger keeps per-field reads.
const STRUCT_PREFETCH_MAX: usize = 0x1000;

impl<'a> StructRef<'a> {
    fn memory(&self) -> AddressSpace<'a, Arc<PhysMem>> {
        self.types.memory()
    }

    /// Read the struct's bytes once so later field reads are served from the
    /// copy: one request per page instead of one per field on a remote
    /// target. Best-effort; an unreadable or oversized struct keeps per-field
    /// reads, which fail or succeed individually as before.
    pub fn prefetch(mut self) -> Self {
        if self.image.is_none() && self.ti.size != 0 && self.ti.size <= STRUCT_PREFETCH_MAX {
            let mut image = vec![0u8; self.ti.size];
            if self.memory().read_bytes(self.base, &mut image).is_ok() {
                self.image = Some(image.into());
            }
        }
        self
    }

    fn read_bytes_at(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        if let Some(image) = &self.image
            && let Some(bytes) = usize::try_from(offset)
                .ok()
                .and_then(|start| image.get(start..start.checked_add(out.len())?))
        {
            out.copy_from_slice(bytes);
            return Ok(());
        }
        self.memory().read_bytes(self.base + offset, out)
    }

    /// Read an integer field at its PDB-declared width (1..=8 bytes).
    pub fn read_uint(&self, name: &str) -> Result<u64> {
        let field = self.field(name)?;
        self.read_uint_at(name, field.offset as u64, field.size)
    }

    fn read_uint_at(&self, name: &str, offset: u64, size: u64) -> Result<u64> {
        let width = usize::try_from(size)
            .map_err(|_| Error::DebugInfo(format!("field '{name}' has invalid integer width")))?;
        if !(1..=8).contains(&width) {
            return Err(Error::DebugInfo(format!(
                "field '{name}' has invalid integer width {width} (expected 1..=8)"
            )));
        }
        let mut bytes = [0u8; 8];
        self.read_bytes_at(offset, &mut bytes[..width])?;
        Ok(le_uint(&bytes[..width]))
    }

    /// Read an address-valued field at its PDB-declared width: 4 bytes in a
    /// 32-bit module's layout, 8 otherwise.
    pub fn read_pointer(&self, name: &str) -> Result<VirtAddr> {
        self.read_uint(name).map(VirtAddr)
    }

    /// Read a field's raw bytes at its PDB-declared size, rejecting a zero
    /// size or one past the caller's bound.
    pub fn read_field_bytes(&self, name: &str, max_len: usize) -> Result<Vec<u8>> {
        let field = self.field(name)?;
        let size = usize::try_from(field.size)
            .map_err(|_| Error::DebugInfo(format!("field '{name}' has invalid byte width")))?;
        if size == 0 {
            return Err(Error::DebugInfo(format!("field '{name}' has no byte size")));
        }
        if size > max_len {
            return Err(Error::DebugInfo(format!(
                "field '{name}' is {size} bytes (maximum {max_len})"
            )));
        }
        let mut bytes = vec![0u8; size];
        self.read_bytes_at(field.offset as u64, &mut bytes)?;
        Ok(bytes)
    }

    fn read_field_at<T: Copy + zerocopy::FromZeros + FromBytes + IntoBytes>(
        &self,
        offset: u64,
    ) -> Result<T> {
        let mut value = T::new_zeroed();
        self.read_bytes_at(offset, value.as_mut_bytes())?;
        Ok(value)
    }

    /// The address this cursor sits at (e.g. to test a followed pointer for
    /// null without another read).
    pub fn addr(&self) -> VirtAddr {
        self.base
    }

    fn field(&self, name: &str) -> Result<&FieldInfo> {
        self.ti
            .fields
            .get(name)
            .ok_or_else(|| Error::FieldNotFound(name.to_string()))
    }

    /// Wrap a freshly resolved layout at `base`, carrying this cursor's context.
    fn with(&self, ti: Arc<TypeInfo>, base: VirtAddr) -> StructRef<'a> {
        self.types.struct_with_layout(ti, base)
    }

    /// Read a scalar field by name. The Rust type `T` (inferred from context)
    /// fixes the read width; the PDB only supplies the offset.
    pub fn read_field<T: Copy + zerocopy::FromZeros + FromBytes + IntoBytes>(
        &self,
        name: &str,
    ) -> Result<T> {
        let offset = self.field(name)?.offset as u64;
        self.read_field_at(offset)
    }

    /// Follow a pointer field to the struct it targets. The target struct type
    /// is taken from the field's own PDB metadata, so the caller never restates
    /// it.
    pub fn follow(&self, name: &str) -> Result<StructRef<'a>> {
        let field = self.field(name)?;
        let ParsedType::Pointer(inner) = &field.type_data else {
            return Err(Error::FieldTypeMismatch(name.to_string(), "pointer".into()));
        };
        let ParsedType::Struct(struct_name) = inner.as_ref() else {
            return Err(Error::FieldTypeMismatch(
                name.to_string(),
                "pointer to struct".into(),
            ));
        };
        let struct_name = struct_name.clone();
        let target = VirtAddr(self.read_uint_at(name, field.offset as u64, field.size)?);
        let ti = self.types.layout(&struct_name)?;
        Ok(self.with(ti, target))
    }

    /// View an embedded sub-struct field as a cursor (no pointer deref). Type
    /// derived from the field's PDB metadata.
    pub fn embedded(&self, name: &str) -> Result<StructRef<'a>> {
        let field = self.field(name)?;
        // Embedded structs and unions both resolve by layout name; nested
        // anonymous unions (e.g. `_IRP.Tail`) are unions, so accept both.
        let type_name = match &field.type_data {
            ParsedType::Struct(n) | ParsedType::Union(n) => n.clone(),
            _ => {
                return Err(Error::FieldTypeMismatch(
                    name.to_string(),
                    "struct or union".into(),
                ));
            }
        };
        let base = self.base + field.offset as u64;
        let ti = self.types.layout(&type_name)?;
        let mut embedded = self.with(ti, base);
        // Carry the enclosing image so the sub-struct's fields stay free.
        if let Some(image) = &self.image {
            let start = field.offset as usize;
            if let Some(bytes) = image.get(start..start + embedded.ti.size) {
                embedded.image = Some(bytes.into());
            }
        }
        Ok(embedded)
    }

    /// Decode the `_UNICODE_STRING` this cursor points at to a Rust `String`
    /// (empty when null/zero-length). Resolves `Length`/`Buffer` from the PDB
    /// rather than hardcoding them.
    pub fn read_unicode_string(&self) -> Result<String> {
        let length: u16 = self.read_field("Length")?;
        let buffer = self.read_pointer("Buffer")?;
        if length == 0 || buffer.is_zero() {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; length as usize];
        self.memory().read_bytes(buffer, &mut buf)?;
        let u16s: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Ok(String::from_utf16_lossy(&u16s))
    }

    /// Decode the `_STRING` (`ANSI_STRING`) this cursor points at, one
    /// character per byte (empty when null/zero-length). Like
    /// [`read_unicode_string`](Self::read_unicode_string), the layout comes
    /// from the PDB.
    pub fn read_ansi_string(&self) -> Result<String> {
        let length: u16 = self.read_field("Length")?;
        let buffer = self.read_pointer("Buffer")?;
        if length == 0 || buffer.is_zero() {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; length as usize];
        self.memory().read_bytes(buffer, &mut buf)?;
        Ok(buf.into_iter().map(char::from).collect())
    }

    /// Decode a `_UNICODE_STRING` field of this struct to a Rust `String`.
    pub fn unicode_string(&self, name: &str) -> Result<String> {
        self.embedded(name)?.read_unicode_string()
    }

    /// Walk an intrusive `_LIST_ENTRY` whose head is `head_field`, yielding a
    /// cursor per record. `record_type` and `link_field` are the one piece the
    /// PDB can't supply (CONTAINING_RECORD isn't type-encoded, and a record may
    /// embed several links). Iteration is bounded and stops on a cycle.
    pub fn list(
        &self,
        head_field: &str,
        record_type: &str,
        link_field: &str,
    ) -> Result<impl Iterator<Item = Result<StructRef<'a>>> + 'a> {
        let head = self.base + self.field(head_field)?.offset as u64;
        self.types.list_at(head, record_type, link_field)
    }
}
