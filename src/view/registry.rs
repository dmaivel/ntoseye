//! The registry (`!reg`) as SDK records: the loaded hives, and keys with
//! their subkeys and values, each value's data typed by its type.

use ntoseye_macros::record;

use crate::target::DiagnosticValue;
use crate::target::etw::format_filetime_precise;
use crate::target::registry::{self as target, KEY_HIVE_EXIT, KEY_SYM_LINK, RegData};
use crate::types::VirtAddr;

/// The cell index bit that selects volatile storage.
const VOLATILE: u32 = 0x8000_0000;

/// A value's data by its type: `str` for REG_SZ, REG_EXPAND_SZ, and
/// REG_LINK, `list[str]` for REG_MULTI_SZ, `int` for REG_DWORD,
/// REG_DWORD_BIG_ENDIAN, and REG_QWORD, and `bytes` for every other
/// type and for a number whose data is not its size.
#[record]
pub enum RegistryData {
    Text(String),
    Strings(Vec<String>),
    Number(u64),
    Raw(#[record(bytes)] Vec<u8>),
}

/// A loaded hive (`_CMHIVE`).
#[record]
pub struct RegistryHive {
    pub address: VirtAddr,
    /// The master hive, whose root is `\\REGISTRY`.
    pub master: bool,
    /// Where it is mounted, such as `\\REGISTRY\\MACHINE\\SYSTEM`.
    pub mount: Option<String>,
    /// The file it was loaded from.
    pub file: Option<String>,
    /// `_HHIVE.BaseBlock`, and the end of the file name it records.
    pub base_block: VirtAddr,
    pub base_block_name: Option<String>,
    /// The cell of its root key.
    #[record(hex)]
    pub root_cell: DiagnosticValue<u32>,
    /// `_HHIVE.Version`, the hive format's minor version.
    pub version: u32,
    /// `_HHIVE.HiveFlags`.
    #[record(hex)]
    pub flags: u32,
    /// The hive is one block of memory, without a cell map.
    pub flat: bool,
    /// The bytes of its stable and volatile storage, and their cell
    /// maps (`_HMAP_DIRECTORY`).
    #[record(hex)]
    pub stable_length: u32,
    pub stable_map: VirtAddr,
    #[record(hex)]
    pub volatile_length: u32,
    pub volatile_map: VirtAddr,
}

/// A hive that does not read.
#[record]
pub struct RegistryUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// The loaded hives (`!reg hivelist`).
#[record]
pub struct RegistryHives {
    pub hives: Vec<RegistryHive>,
    pub unreadable: Vec<RegistryUnreadable>,
    /// Why the walk of `nt!CmpHiveListHead` stopped short.
    pub stopped: Option<String>,
}

/// A symbolic link a path went through: the link's path and the path
/// its `SymbolicLinkValue` holds.
#[record]
pub struct RegistryLink {
    pub path: String,
    pub target: String,
}

/// A subkey as its parent lists it.
#[record]
pub struct RegistrySubkey {
    pub name: String,
    #[record(hex)]
    pub cell: u32,
    /// Its key node (`_CM_KEY_NODE`).
    pub node: VirtAddr,
    /// `_CM_KEY_NODE.Flags`.
    #[record(hex)]
    pub flags: u16,
    pub volatile: bool,
    /// The key is a symbolic link.
    pub symbolic_link: bool,
    /// A hive is mounted at the key.
    pub mount_point: bool,
    /// A FILETIME, and as UTC.
    pub last_write: u64,
    pub last_write_utc: Option<String>,
    pub subkey_count: u32,
    pub value_count: u32,
}

/// A value (`_CM_KEY_VALUE`).
#[record]
pub struct RegistryValue {
    /// Empty for the default value.
    pub name: String,
    /// `REG_*`.
    #[record(hex)]
    pub r#type: u32,
    /// The type's name; `None` for a type Windows does not define.
    pub type_name: Option<&'static str>,
    #[record(hex)]
    pub cell: u32,
    pub node: VirtAddr,
    /// The data's length in bytes.
    pub length: u32,
    /// Where the data is: `inline` in the value record, in a `cell`,
    /// or in `big` data segments.
    pub storage: &'static str,
    /// The data decoded by the value's type.
    pub data: DiagnosticValue<RegistryData>,
    /// The data's bytes.
    #[record(bytes)]
    pub raw: DiagnosticValue<Vec<u8>>,
}

/// A subkey or value cell that does not read.
#[record]
pub struct RegistryCellError {
    #[record(hex)]
    pub cell: u32,
    pub error: String,
}

/// A key with its subkeys and values (`!reg querykey`).
#[record]
pub struct RegistryKey {
    /// Its full path, with the names as the hives store them.
    pub path: String,
    pub hive: VirtAddr,
    /// Its cell; `None` for a key read by the address of its node.
    #[record(hex)]
    pub cell: Option<u32>,
    pub node: VirtAddr,
    pub name: String,
    #[record(hex)]
    pub flags: u16,
    /// The `KEY_*` names of `flags`.
    pub flag_names: Vec<&'static str>,
    /// A FILETIME, and as UTC.
    pub last_write: u64,
    pub last_write_utc: Option<String>,
    /// The symbolic links the path went through.
    pub links: Vec<RegistryLink>,
    /// The subkeys and values the key node counts.
    pub subkey_count: u32,
    pub value_count: u32,
    pub subkeys: Vec<RegistrySubkey>,
    #[record(rename = "values")]
    pub key_values: Vec<RegistryValue>,
    pub unreadable_subkeys: Vec<RegistryCellError>,
    pub unreadable_values: Vec<RegistryCellError>,
    /// Subkey indexes and value lists that do not read, and counts that
    /// do not match.
    pub problems: Vec<String>,
}

/// Where a cell of a hive is (`!reg cellindex`).
#[record]
pub struct RegistryCell {
    pub hive: VirtAddr,
    #[record(hex)]
    pub cell: u32,
    pub volatile: bool,
    /// The cell map directory and table indexes and the offset in the
    /// block, from the cell index; `None` in a flat hive.
    pub directory: Option<u32>,
    pub table: Option<u32>,
    #[record(hex)]
    pub offset: Option<u32>,
    /// The block's `_HMAP_ENTRY`, and where it maps the block: its
    /// place in the bin that holds it.
    pub map_entry: Option<VirtAddr>,
    pub block: Option<VirtAddr>,
    /// The cell: its size field, which its data follows.
    pub address: VirtAddr,
    /// The size field: negative for a cell in use.
    pub size: DiagnosticValue<i32>,
}

fn data(data: RegData) -> RegistryData {
    match data {
        RegData::Text(text) => RegistryData::Text(text),
        RegData::Strings(strings) => RegistryData::Strings(strings),
        RegData::Number(number) => RegistryData::Number(number),
        RegData::Bytes(bytes) => RegistryData::Raw(bytes),
    }
}

fn hive(hive: &target::Hive) -> RegistryHive {
    RegistryHive {
        address: hive.address,
        master: hive.master,
        mount: hive.mount.clone(),
        file: hive.file.clone(),
        base_block: hive.base_block,
        base_block_name: hive.base_block_name.clone(),
        root_cell: hive.root_cell.clone(),
        version: hive.version,
        flags: hive.flags,
        flat: hive.flat,
        stable_length: hive.stable.length,
        stable_map: hive.stable.map,
        volatile_length: hive.volatile.length,
        volatile_map: hive.volatile.map,
    }
}

pub fn hives(list: &target::HiveList) -> RegistryHives {
    let mut hives = Vec::new();
    let mut unreadable = Vec::new();
    for entry in &list.hives {
        match entry {
            Ok(value) => hives.push(hive(value)),
            Err((address, error)) => unreadable.push(RegistryUnreadable {
                address: *address,
                error: error.clone(),
            }),
        }
    }
    RegistryHives {
        hives,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn value(value: &target::RegValue) -> RegistryValue {
    RegistryValue {
        name: value.name.clone(),
        r#type: value.value_type,
        type_name: target::value_type_name(value.value_type),
        cell: value.cell,
        node: value.node,
        length: value.length,
        storage: match value.storage {
            target::DataStorage::Inline => "inline",
            target::DataStorage::Cell => "cell",
            target::DataStorage::Big => "big",
        },
        data: match value.decoded() {
            DiagnosticValue::Available(decoded) => DiagnosticValue::Available(data(decoded)),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error),
        },
        raw: value.data.clone(),
    }
}

fn cell_errors<T>(entries: &[std::result::Result<T, (u32, String)>]) -> Vec<RegistryCellError> {
    entries
        .iter()
        .filter_map(|entry| entry.as_ref().err())
        .map(|(cell, error)| RegistryCellError {
            cell: *cell,
            error: error.clone(),
        })
        .collect()
}

pub fn key(key: &target::RegKey) -> RegistryKey {
    RegistryKey {
        path: key.path.clone(),
        hive: key.hive,
        cell: key.cell,
        node: key.node,
        name: key.name.clone(),
        flags: key.flags,
        flag_names: target::key_flag_names(key.flags),
        last_write: key.last_write,
        last_write_utc: format_filetime_precise(key.last_write),
        links: key
            .links
            .iter()
            .map(|link| RegistryLink {
                path: link.from.clone(),
                target: link.to.clone(),
            })
            .collect(),
        subkey_count: key.subkey_count,
        value_count: key.value_count,
        subkeys: key
            .subkeys
            .iter()
            .flatten()
            .map(|subkey| RegistrySubkey {
                name: subkey.name.clone(),
                cell: subkey.cell,
                node: subkey.node,
                flags: subkey.flags,
                volatile: subkey.cell & VOLATILE != 0,
                symbolic_link: subkey.flags & KEY_SYM_LINK != 0,
                mount_point: subkey.flags & KEY_HIVE_EXIT != 0,
                last_write: subkey.last_write,
                last_write_utc: format_filetime_precise(subkey.last_write),
                subkey_count: subkey.subkeys,
                value_count: subkey.values,
            })
            .collect(),
        key_values: key.values.iter().flatten().map(value).collect(),
        unreadable_subkeys: cell_errors(&key.subkeys),
        unreadable_values: cell_errors(&key.values),
        problems: key.problems.clone(),
    }
}

pub fn cell(location: &target::CellLocation) -> RegistryCell {
    RegistryCell {
        hive: location.hive,
        cell: location.cell,
        volatile: location.volatile,
        directory: location.map.map(|map| map.directory),
        table: location.map.map(|map| map.table),
        offset: location.map.map(|map| map.offset),
        map_entry: location.map.map(|map| map.entry),
        block: location.map.map(|map| map.block),
        address: location.address,
        size: location.size.clone(),
    }
}
