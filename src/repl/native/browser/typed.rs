//! The memory pane's typed layout (`t`): the memory at an address read as a
//! PDB type, a row per field as `dt` lists them, nested structures and
//! arrays opening in place, pointers and list links followed to what they
//! lead to.

use std::collections::{HashMap, HashSet};

use crate::layout::{
    FieldInfo, ParsedType, TypeInfo, named_type, nested_layout_name, utf16le_lossy,
};
use crate::session::Session;
use crate::types::VirtAddr;
use crate::typeview::TypeView;

/// The most elements an open array lists.
const ARRAY_ROWS: usize = 64;
/// The most rows a view lists: a type opened all the way down can run to
/// thousands.
const ROW_LIMIT: usize = 2048;

/// Kernel object types by the name their `_OBJECT_TYPE` gives: the layout
/// of the body, and the field where the body says what it is, with the
/// values it holds there. A guess needs both the header and the body to
/// agree, as a header decoded from stray bytes rarely names a type whose
/// body matches too.
const OBJECT_TYPES: &[(&str, &str, &str, &[u64])] = &[
    ("Process", "nt!_EPROCESS", "Pcb.Header.Type", &[3]),
    ("Thread", "nt!_ETHREAD", "Tcb.Header.Type", &[6]),
    ("Event", "nt!_KEVENT", "Header.Type", &[0, 1]),
    ("Mutant", "nt!_KMUTANT", "Header.Type", &[2]),
    ("Semaphore", "nt!_KSEMAPHORE", "Header.Type", &[5]),
    ("File", "nt!_FILE_OBJECT", "Type", &[5]),
    ("Device", "nt!_DEVICE_OBJECT", "Type", &[3]),
    ("Driver", "nt!_DRIVER_OBJECT", "Type", &[4]),
];

/// An instance of a type in memory, and which of its fields are open.
pub struct Typed {
    /// The type as it was named (`nt!_EPROCESS`), for the location line and
    /// the type field.
    pub type_name: String,
    pub size: usize,
    /// Where the instance starts.
    pub base: u64,
    /// The paths of the open fields (`Pcb`, `Pcb.Header`, `Threads[2]`).
    pub open: HashSet<String>,
    pub rows: Vec<Row>,
    /// The row under the cursor, an index into `rows`.
    pub cursor: usize,
    /// Each row's value at the last look, by path.
    seen: HashMap<String, String>,
    /// The rows whose value changed since the look before, by path.
    pub changed: HashSet<String>,
    /// The rows left out past [`ROW_LIMIT`].
    pub cut: bool,
}

/// What a row is, which decides what its keys do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A nested structure or union: it opens in place.
    Aggregate,
    /// An array: its elements open in place.
    Array,
    /// A `_LIST_ENTRY`: it opens in place, and Enter follows its Flink to
    /// the next record of the same type.
    Link,
    /// A flags word the PDB also declares bit by bit: its bits open in
    /// place, and its value names the ones set.
    Flags,
    /// A pointer: Enter follows it.
    Pointer,
    /// A number, an enum, a flag or a string.
    Scalar,
    /// A line about the rows above it, such as the elements left out.
    Note,
}

pub struct Row {
    pub path: String,
    pub depth: usize,
    /// The field's name, or an element's `[index]`.
    pub name: String,
    pub type_name: String,
    /// The field's offset from the start of the instance.
    pub offset: u64,
    pub address: u64,
    pub size: usize,
    /// The value as `dt` writes it; empty for a structure or an array.
    pub value: String,
    /// The number the field holds, when it is one: a pointer's target, a
    /// list link's Flink.
    pub raw: Option<u64>,
    pub kind: Kind,
    /// The layout a pointer points to, when the PDB has it.
    pub pointee: Option<String>,
    /// A flags word's bits that are set, by name, with the value of a
    /// field wider than a bit: `PrimaryTokenFrozen DefaultPagePriority=5`.
    pub set: String,
    /// A bitfield's position and width in the word at `address`.
    pub bits: Option<(u8, u8)>,
}

impl Row {
    /// Whether the row opens in place.
    pub fn opens(&self) -> bool {
        matches!(
            self.kind,
            Kind::Aggregate | Kind::Array | Kind::Link | Kind::Flags
        )
    }

    /// Whether `e` writes the row: a number, a pointer or a flags word of
    /// 1, 2, 4 or 8 bytes, or a bit of one.
    pub fn writable(&self) -> bool {
        matches!(self.kind, Kind::Scalar | Kind::Pointer | Kind::Flags)
            && matches!(self.size, 1 | 2 | 4 | 8)
    }
}

impl Typed {
    /// `type_name` at `base`, with no field open.
    pub fn new(session: &Session, type_name: &str, base: u64) -> Result<Self, String> {
        let view = TypeView::new(session);
        let info = view
            .lookup_type(type_name)
            .ok_or_else(|| format!("no loaded PDB describes the type {type_name}"))?;
        let mut typed = Self {
            type_name: type_name.to_owned(),
            size: info.size,
            base,
            open: HashSet::new(),
            rows: Vec::new(),
            cursor: 0,
            seen: HashMap::new(),
            changed: HashSet::new(),
            cut: false,
        };
        typed.read(session);
        Ok(typed)
    }

    /// Read the rows again, keeping the cursor on the field it was on, and
    /// mark the values that changed since the last read.
    pub fn read(&mut self, session: &Session) {
        let at = self.rows.get(self.cursor).map(|row| row.path.clone());
        let view = TypeView::new(session);
        let Some(info) = view.lookup_type(&self.type_name) else {
            self.rows.clear();
            return;
        };
        let mut rows = Vec::new();
        struct_rows(
            &view, &info, self.base, self.base, "", 0, &self.open, &mut rows,
        );
        self.cut = rows.len() >= ROW_LIMIT;
        self.changed = rows
            .iter()
            .filter(|row| {
                self.seen
                    .get(&row.path)
                    .is_some_and(|seen| *seen != row.value)
            })
            .map(|row| row.path.clone())
            .collect();
        self.seen = rows
            .iter()
            .map(|row| (row.path.clone(), row.value.clone()))
            .collect();
        self.rows = rows;
        self.cursor = at
            .and_then(|path| self.rows.iter().position(|row| row.path == path))
            .unwrap_or(0)
            .min(self.rows.len().saturating_sub(1));
    }

    pub fn row(&self) -> Option<&Row> {
        self.rows.get(self.cursor)
    }

    /// Open the row under the cursor, or close it when it is open.
    pub fn toggle(&mut self, session: &Session) {
        let Some(row) = self.row().filter(|row| row.opens()) else {
            return;
        };
        let path = row.path.clone();
        if !self.open.remove(&path) {
            self.open.insert(path);
        }
        self.read(session);
    }

    /// Open the row under the cursor; whether it opened.
    pub fn open_row(&mut self, session: &Session) -> bool {
        match self.row() {
            Some(row) if row.opens() && !self.open.contains(&row.path) => {
                self.open.insert(row.path.clone());
                self.read(session);
                true
            }
            _ => false,
        }
    }

    /// Close the row under the cursor when it is open, else go to the row
    /// it is in.
    pub fn close_row(&mut self, session: &Session) {
        let Some(row) = self.row() else {
            return;
        };
        let (path, depth) = (row.path.clone(), row.depth);
        if self.open.remove(&path) {
            self.read(session);
            return;
        }
        if depth == 0 {
            return;
        }
        if let Some(parent) = self.rows[..self.cursor]
            .iter()
            .rposition(|row| row.depth < depth)
        {
            self.cursor = parent;
        }
    }

    /// The record the list link under the cursor leads to: its Flink less
    /// the link's offset, an instance of the same type.
    pub fn next_record(&self) -> Result<u64, String> {
        let row = self
            .row()
            .filter(|row| row.kind == Kind::Link)
            .ok_or("not a list link")?;
        match row.raw {
            Some(0) => Err("the Flink is null".into()),
            Some(flink) => Ok(flink.wrapping_sub(row.offset)),
            None => Err(format!("the Flink at {:#x} cannot be read", row.address)),
        }
    }
}

/// `info`'s fields at `base`, the open ones followed by theirs, under
/// `prefix`. A bitfield that overlays a word of its own size at its offset
/// (`Flags2` and `JobNotReallyActive : 1`) is that word's, shown when the
/// word is open.
#[allow(clippy::too_many_arguments)]
fn struct_rows(
    view: &TypeView<'_>,
    info: &TypeInfo,
    base: u64,
    root: u64,
    prefix: &str,
    depth: usize,
    open: &HashSet<String>,
    rows: &mut Vec<Row>,
) {
    let fields = info.fields_in_order();
    let word_of = |bit: &FieldInfo| -> Option<&String> {
        let ParsedType::Bitfield { underlying, .. } = &bit.type_data else {
            return None;
        };
        let size = view.parsed_type_size(underlying);
        fields
            .iter()
            .find(|(_, word)| {
                word.offset == bit.offset
                    && matches!(word.type_data, ParsedType::Primitive(_))
                    && view.field_size(word) == size
            })
            .map(|(name, _)| *name)
    };
    for (name, field) in &fields {
        if rows.len() >= ROW_LIMIT {
            return;
        }
        if word_of(field).is_some() {
            continue;
        }
        let path = if prefix.is_empty() {
            (*name).clone()
        } else {
            format!("{prefix}.{name}")
        };
        let address = base.wrapping_add(u64::from(field.offset));
        let bits: Vec<(&String, &FieldInfo)> = fields
            .iter()
            .filter(|(_, bit)| word_of(bit) == Some(*name))
            .copied()
            .collect();
        if bits.is_empty() {
            value_rows(
                view,
                field,
                (*name).clone(),
                path,
                address,
                root,
                depth,
                open,
                rows,
            );
        } else {
            flags_rows(
                view, field, name, &bits, path, address, root, depth, open, rows,
            );
        }
    }
}

/// A flags word's row, its value naming the bits set, then its bits when
/// it is open.
#[allow(clippy::too_many_arguments)]
fn flags_rows(
    view: &TypeView<'_>,
    word: &FieldInfo,
    name: &str,
    bits: &[(&String, &FieldInfo)],
    path: String,
    address: u64,
    root: u64,
    depth: usize,
    open: &HashSet<String>,
    rows: &mut Vec<Row>,
) {
    let (value, raw) = view.value_and_raw(VirtAddr(address), word);
    let set = raw.map_or_else(String::new, |raw| {
        bits.iter()
            .filter_map(|(bit, field)| {
                let ParsedType::Bitfield { len, .. } = field.type_data else {
                    return None;
                };
                match field.decode(raw) {
                    0 => None,
                    _ if len == 1 => Some((*bit).clone()),
                    value => Some(format!("{bit}={value:#x}")),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    });
    rows.push(Row {
        path: path.clone(),
        depth,
        name: name.to_owned(),
        type_name: word.type_data.to_string(),
        offset: address.wrapping_sub(root),
        address,
        size: view.field_size(word),
        value,
        raw,
        kind: Kind::Flags,
        pointee: None,
        set,
        bits: None,
    });
    if !open.contains(&path) {
        return;
    }
    for (bit, field) in bits {
        value_rows(
            view,
            field,
            (*bit).clone(),
            format!("{path}.{bit}"),
            address,
            root,
            depth + 1,
            open,
            rows,
        );
    }
}

/// The row of a field or an element, then the rows of what it holds when
/// it is open.
#[allow(clippy::too_many_arguments)]
fn value_rows(
    view: &TypeView<'_>,
    field: &FieldInfo,
    name: String,
    path: String,
    address: u64,
    root: u64,
    depth: usize,
    open: &HashSet<String>,
    rows: &mut Vec<Row>,
) {
    let (mut value, mut raw) = view.value_and_raw(VirtAddr(address), field);
    let kind = match &field.type_data {
        ParsedType::Pointer(_) => Kind::Pointer,
        data if named_type(data, "_LIST_ENTRY") => Kind::Link,
        ParsedType::Struct(_) | ParsedType::Union(_)
            if !named_type(&field.type_data, "_UNICODE_STRING") =>
        {
            Kind::Aggregate
        }
        ParsedType::Array(_, count) if *count > 0 && field.type_data.c_string_len().is_none() => {
            Kind::Array
        }
        _ => Kind::Scalar,
    };
    if kind == Kind::Link {
        // The Flink, where Enter goes; its width is the link's half.
        let size = (view.field_size(field) / 2).clamp(4, 8);
        raw = view.read_display_uint(VirtAddr(address), size).ok();
    }
    // A wide-character array reads as its text, as `dt` shows it in WinDbg.
    if let ParsedType::Array(element, count) = &field.type_data
        && matches!(element.as_ref(), ParsedType::Primitive(name) if matches!(name.as_str(), "WCHAR" | "wchar_t"))
    {
        value = wide_text(view, address, *count);
    }
    let pointee = match &field.type_data {
        ParsedType::Pointer(inner) => {
            nested_layout_name(inner).filter(|name| view.lookup_type(name).is_some())
        }
        _ => None,
    };
    let size = view.field_size(field);
    let is_open = open.contains(&path);
    rows.push(Row {
        path: path.clone(),
        depth,
        name,
        type_name: field.type_data.to_string(),
        offset: address.wrapping_sub(root),
        address,
        size,
        value,
        raw,
        kind,
        pointee,
        set: String::new(),
        bits: match &field.type_data {
            ParsedType::Bitfield { pos, len, .. } => Some((*pos, *len)),
            _ => None,
        },
    });
    if !is_open {
        return;
    }
    match (&kind, &field.type_data) {
        (Kind::Aggregate | Kind::Link, data) => {
            let Some(info) = nested_layout_name(data).and_then(|name| view.lookup_type(&name))
            else {
                return;
            };
            struct_rows(view, &info, address, root, &path, depth + 1, open, rows);
        }
        (Kind::Array, ParsedType::Array(element, count)) => {
            let Some(stride) = view.element_stride(size, element, *count) else {
                return;
            };
            let shown = (*count as usize).min(ARRAY_ROWS);
            for index in 0..shown {
                if rows.len() >= ROW_LIMIT {
                    return;
                }
                let element_field = FieldInfo {
                    offset: 0,
                    size: stride as u64,
                    type_data: element.as_ref().clone(),
                };
                let at = address.wrapping_add((index * stride) as u64);
                value_rows(
                    view,
                    &element_field,
                    format!("[{index}]"),
                    format!("{path}[{index}]"),
                    at,
                    root,
                    depth + 1,
                    open,
                    rows,
                );
            }
            if shown < *count as usize {
                rows.push(Row {
                    path: format!("{path}[…]"),
                    depth: depth + 1,
                    name: format!("… {} more elements", *count as usize - shown),
                    type_name: String::new(),
                    offset: address
                        .wrapping_add((shown * stride) as u64)
                        .wrapping_sub(root),
                    address: address.wrapping_add((shown * stride) as u64),
                    size: 0,
                    value: String::new(),
                    raw: None,
                    kind: Kind::Note,
                    pointee: None,
                    set: String::new(),
                    bits: None,
                });
            }
        }
        _ => {}
    }
}

/// The UTF-16 text of a `WCHAR[count]` at `address`, up to its first NUL,
/// quoted; empty when it can't be read.
fn wide_text(view: &TypeView<'_>, address: u64, count: u32) -> String {
    const MOST: usize = 256;
    let units = (count as usize).min(MOST);
    let Ok(bytes) = view.read_display_bytes(VirtAddr(address), units * 2) else {
        return String::new();
    };
    let text = utf16le_lossy(&bytes);
    format!("\"{}\"", text.split('\0').next().unwrap_or_default())
}

/// The layout of the kernel object whose body starts at `address`, when
/// its header and its body say the same: what the type field offers first.
pub fn guess(session: &Session, address: u64) -> Option<&'static str> {
    let header = session
        .target
        .inspect_object_header(VirtAddr(address))
        .ok()
        .filter(|header| header.body.0 == address)?;
    let name = header.type_name?;
    let &(_, layout, field, values) = OBJECT_TYPES
        .iter()
        .find(|(type_name, ..)| *type_name == name)?;
    let (_, offset) = resolve(session, &format!("{layout}.{field}")).ok()?;
    let value = TypeView::new(session)
        .read_display_uint(VirtAddr(address.wrapping_add(offset)), 1)
        .ok()?;
    values.contains(&value).then_some(layout)
}

/// `type` or `type.Field.Path` as typed in the type field: the type and the
/// offset of the field in it, so the cursor's address can be that field.
pub fn resolve(session: &Session, text: &str) -> Result<(String, u64), String> {
    let view = TypeView::new(session);
    // A module qualifier's `!` comes before the first dot of the path.
    let (type_name, path) = match text.find('.') {
        Some(dot) => (&text[..dot], Some(&text[dot + 1..])),
        None => (text, None),
    };
    let info = view
        .lookup_type(type_name)
        .ok_or_else(|| format!("no loaded PDB describes the type {type_name}"))?;
    let Some(path) = path else {
        return Ok((type_name.to_owned(), 0));
    };
    let mut offset = 0u64;
    let mut current = info;
    let names: Vec<&str> = path.split('.').collect();
    for (index, name) in names.iter().enumerate() {
        let field = current
            .field(name)
            .map_err(|_| format!("{type_name} has no field {path}"))?;
        offset += u64::from(field.offset);
        if index + 1 == names.len() {
            break;
        }
        current = match &field.type_data {
            ParsedType::Struct(_) | ParsedType::Union(_) => nested_layout_name(&field.type_data)
                .and_then(|nested| view.lookup_type(&nested))
                .ok_or_else(|| format!("the type of {name} is not in a loaded PDB"))?,
            _ => return Err(format!("{name} is not a nested structure")),
        };
    }
    Ok((type_name.to_owned(), offset))
}
