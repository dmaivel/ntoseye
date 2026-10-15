//! The configuration manager's registry (`!reg`): the hives loaded in kernel
//! memory, and the keys and values in them.
//!
//! The kernel keeps each loaded hive (`_CMHIVE`) on `nt!CmpHiveListHead`. A
//! hive's data is a run of bins of cells, each named by a cell index: its
//! high bit selects the stable or the volatile storage, and the rest is an
//! offset into that storage, which the storage's cell map
//! (`_HHIVE.Storage[].Map`, a directory of tables of `_HMAP_ENTRY`)
//! translates to the address of the bin that holds it. The bins of a hive
//! loaded from a file are views of the file in the address space of the
//! Registry process, the minimal process the kernel creates for them, so
//! cells are read through its page tables, which map the hives in pool as
//! well. A bin whose pages are not in memory leaves its cells unavailable,
//! each reported on its own.
//!
//! Keys (`nk`), subkey indexes (`lf`, `lh`, `li`, `ri`), values (`vk`), and
//! big data (`db`) are records of the hive file format, decoded with the
//! kernel's layouts of them (`_CM_KEY_NODE`, `_CM_KEY_INDEX`, `_CM_INDEX`,
//! `_CM_KEY_VALUE`, `_CM_BIG_DATA`) where its PDB has them and at the
//! format's own (64-bit) offsets otherwise. A path resolves the way the
//! kernel parses one: from the master hive's root, `\REGISTRY`, across the
//! link node of each hive mounted below it, and through symbolic links
//! such as `CurrentControlSet`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use super::{DiagnosticValue, Target, bounded_record_list_walk};
use crate::error::{Error, Result};
use crate::layout::{TypeInfo, Types, utf16le_lossy, utf16le_nul_terminated};
use crate::memory::{AddressSpace, MemoryOps};
use crate::phys::PhysMem;
use crate::types::VirtAddr;

const MAX_HIVES: usize = 4096;
/// The most subkeys, or values, read of one key.
const MAX_CHILDREN: usize = 0x10_0000;
/// The largest cell read. A cell lies in one bin, which the hive format
/// keeps far smaller.
const MAX_CELL: usize = 0x40_0000;
/// The most data read of one value.
const MAX_VALUE_DATA: usize = 0x100_0000;
/// The most symbolic links one path follows.
const MAX_REPARSE: usize = 16;
/// The most parents walked up from a key to its hive's root.
const MAX_DEPTH: usize = 512;

/// `_HHIVE.Signature`.
const HHIVE_SIGNATURE: u64 = 0xbee0_bee0;
/// The cell index bit that selects volatile storage.
const HCELL_VOLATILE: u32 = 0x8000_0000;
const HCELL_NIL: u32 = u32::MAX;
/// The size of a hive block, the unit the cell map maps.
const HBLOCK_SIZE: u64 = 0x1000;
/// The low bits of `_HMAP_ENTRY.PermanentBinAddress` that hold flags.
const HMAP_FLAGS: u64 = 0xf;
/// The size field that precedes a cell's data.
const CELL_HEADER: u64 = 4;

/// The key is volatile.
pub const KEY_VOLATILE: u16 = 0x0001;
/// The key is a link node to the root of a hive mounted at it.
pub const KEY_HIVE_EXIT: u16 = 0x0002;
/// The key is the root of its hive.
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_NO_DELETE: u16 = 0x0008;
/// The key is a symbolic link, to the path its `SymbolicLinkValue` holds.
pub const KEY_SYM_LINK: u16 = 0x0010;
/// The key's name is stored one byte per character.
pub const KEY_COMP_NAME: u16 = 0x0020;
const VALUE_COMP_NAME: u16 = 0x0001;
/// `_CM_KEY_VALUE.DataLength` bit: the data is in the `Data` field itself.
const CM_KEY_VALUE_SPECIAL_SIZE: u32 = 0x8000_0000;
/// The most data one cell holds; longer data is split into big data
/// segments of this size.
const CM_KEY_VALUE_BIG: usize = 0x3fd8;
/// The first hive version that stores big data.
const HSYS_WHISTLER_BETA1: u32 = 4;

const SIG_NK: u16 = u16::from_le_bytes(*b"nk");
/// A link node, a key node that links to a hive mounted at it.
const SIG_LK: u16 = u16::from_le_bytes(*b"lk");
const SIG_VK: u16 = u16::from_le_bytes(*b"vk");
const SIG_LF: u16 = u16::from_le_bytes(*b"lf");
const SIG_LH: u16 = u16::from_le_bytes(*b"lh");
const SIG_LI: u16 = u16::from_le_bytes(*b"li");
const SIG_RI: u16 = u16::from_le_bytes(*b"ri");
const SIG_DB: u16 = u16::from_le_bytes(*b"db");

/// The value that holds a symbolic link's target.
const SYMBOLIC_LINK_VALUE: &str = "SymbolicLinkValue";
/// The image name of the process whose address space holds the hives'
/// views of their files.
const REGISTRY_PROCESS: &str = "Registry";

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;

/// The name of a value type, `None` for a type Windows does not define
/// (device properties use types of their own, such as `0xffff0012`).
pub fn value_type_name(value_type: u32) -> Option<&'static str> {
    Some(match value_type {
        REG_NONE => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN",
        REG_LINK => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_RESOURCE_LIST => "REG_RESOURCE_LIST",
        REG_FULL_RESOURCE_DESCRIPTOR => "REG_FULL_RESOURCE_DESCRIPTOR",
        REG_RESOURCE_REQUIREMENTS_LIST => "REG_RESOURCE_REQUIREMENTS_LIST",
        REG_QWORD => "REG_QWORD",
        _ => return None,
    })
}

/// The names of the `KEY_*` flags set in a key node's `Flags`.
pub fn key_flag_names(flags: u16) -> Vec<&'static str> {
    const NAMES: [(u16, &str); 10] = [
        (KEY_VOLATILE, "KEY_VOLATILE"),
        (KEY_HIVE_EXIT, "KEY_HIVE_EXIT"),
        (KEY_HIVE_ENTRY, "KEY_HIVE_ENTRY"),
        (KEY_NO_DELETE, "KEY_NO_DELETE"),
        (KEY_SYM_LINK, "KEY_SYM_LINK"),
        (KEY_COMP_NAME, "KEY_COMP_NAME"),
        (0x0040, "KEY_PREDEF_HANDLE"),
        (0x0080, "KEY_VIRT_MIRRORED"),
        (0x0100, "KEY_VIRT_TARGET"),
        (0x0200, "KEY_VIRTUAL_STORE"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// A value's data, decoded by its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegData {
    /// `REG_SZ`, `REG_EXPAND_SZ`, and `REG_LINK`: the string up to its first
    /// NUL.
    Text(String),
    /// `REG_MULTI_SZ`: the strings up to the empty one that ends the list.
    Strings(Vec<String>),
    /// `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, and `REG_QWORD`.
    Number(u64),
    /// Every other type, and a number whose data is not its size.
    Bytes(Vec<u8>),
}

impl RegData {
    pub fn decode(value_type: u32, bytes: &[u8]) -> Self {
        match value_type {
            REG_SZ | REG_EXPAND_SZ | REG_LINK => Self::Text(utf16le_nul_terminated(bytes)),
            REG_MULTI_SZ => {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&unit| u16::from_le_bytes(unit))
                    .collect();
                Self::Strings(
                    units
                        .split(|&unit| unit == 0)
                        .take_while(|string| !string.is_empty())
                        .map(String::from_utf16_lossy)
                        .collect(),
                )
            }
            REG_DWORD if bytes.len() == 4 => {
                Self::Number(u32::from_le_bytes(bytes.try_into().unwrap()).into())
            }
            REG_DWORD_BIG_ENDIAN if bytes.len() == 4 => {
                Self::Number(u32::from_be_bytes(bytes.try_into().unwrap()).into())
            }
            REG_QWORD if bytes.len() == 8 => {
                Self::Number(u64::from_le_bytes(bytes.try_into().unwrap()))
            }
            _ => Self::Bytes(bytes.to_vec()),
        }
    }
}

/// One of a hive's two storages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiveStorage {
    /// `_DUAL.Length`: the bytes of cells it holds.
    pub length: u32,
    /// `_DUAL.Map`: its cell map's directory.
    pub map: VirtAddr,
}

/// A loaded hive (`_CMHIVE`).
#[derive(Debug, Clone)]
pub struct Hive {
    pub address: VirtAddr,
    /// The master hive (`nt!CmpMasterHive`), whose root is `\REGISTRY`.
    pub master: bool,
    /// Where it is mounted (`HiveRootPath`), `\REGISTRY` for the master
    /// hive.
    pub mount: Option<String>,
    /// The file it was loaded from (`FileUserName`, else `FileFullPath`).
    pub file: Option<String>,
    /// `_HHIVE.BaseBlock`, and the end of the file's name it records.
    pub base_block: VirtAddr,
    pub base_block_name: Option<String>,
    /// `_HBASE_BLOCK.RootCell`, the cell of its root key.
    pub root_cell: DiagnosticValue<u32>,
    /// `_HHIVE.Version`, the format's minor version.
    pub version: u32,
    /// `_HHIVE.HiveFlags`.
    pub flags: u32,
    /// The hive is one block of memory (a hive the boot loader loaded, read
    /// before its cell map exists).
    pub flat: bool,
    pub stable: HiveStorage,
    pub volatile: HiveStorage,
}

pub type HiveEntry = std::result::Result<Hive, (VirtAddr, String)>;

/// The loaded hives (`!reg hivelist`).
#[derive(Debug, Clone)]
pub struct HiveList {
    pub hives: Vec<HiveEntry>,
    /// Why the walk of `nt!CmpHiveListHead` stopped short.
    pub stopped: Option<String>,
}

/// Where a cell is (`!reg cellindex`).
#[derive(Debug, Clone)]
pub struct CellLocation {
    pub hive: VirtAddr,
    pub cell: u32,
    pub volatile: bool,
    /// The directory and table indexes and the offset in the block, from
    /// the cell index; `None` in a flat hive, which has no cell map.
    pub map: Option<CellMapPath>,
    /// The cell: its size field, which its data follows.
    pub address: VirtAddr,
    /// The cell's size field: negative for a cell in use.
    pub size: DiagnosticValue<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellMapPath {
    pub directory: u32,
    pub table: u32,
    pub offset: u32,
    /// The `_HMAP_ENTRY` of the cell's block.
    pub entry: VirtAddr,
    /// Where the entry maps the block: its place in the bin that holds it.
    pub block: VirtAddr,
}

/// A symbolic link a path went through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegLink {
    pub from: String,
    pub to: String,
}

/// A subkey as its parent lists it.
#[derive(Debug, Clone)]
pub struct RegSubkey {
    pub name: String,
    pub cell: u32,
    /// Its key node (`_CM_KEY_NODE`).
    pub node: VirtAddr,
    pub flags: u16,
    /// A FILETIME.
    pub last_write: u64,
    pub subkeys: u32,
    pub values: u32,
}

/// Where a value's data is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStorage {
    /// In the value record itself (up to 4 bytes).
    Inline,
    /// In one cell.
    Cell,
    /// In the segments of a big data record (`db`).
    Big,
}

/// A value (`_CM_KEY_VALUE`).
#[derive(Debug, Clone)]
pub struct RegValue {
    /// Empty for the key's default value.
    pub name: String,
    pub cell: u32,
    pub node: VirtAddr,
    pub value_type: u32,
    /// The data's length in bytes.
    pub length: u32,
    pub storage: DataStorage,
    pub data: DiagnosticValue<Vec<u8>>,
}

impl RegValue {
    /// The data decoded by the value's type.
    pub fn decoded(&self) -> DiagnosticValue<RegData> {
        self.data
            .map(|bytes| RegData::decode(self.value_type, bytes))
    }
}

/// A subkey, or the cell of one that does not read and why.
pub type RegSubkeyEntry = std::result::Result<RegSubkey, (u32, String)>;
/// A value, or the cell of one that does not read and why.
pub type RegValueEntry = std::result::Result<RegValue, (u32, String)>;

/// A key with its subkeys and values (`!reg querykey`, `!reg keyinfo`).
#[derive(Debug, Clone)]
pub struct RegKey {
    /// Its full path, with the names as the hives store them.
    pub path: String,
    pub hive: VirtAddr,
    /// Its cell; `None` for a key given by the address of its node.
    pub cell: Option<u32>,
    pub node: VirtAddr,
    pub name: String,
    pub flags: u16,
    /// A FILETIME.
    pub last_write: u64,
    /// The symbolic links the path went through.
    pub links: Vec<RegLink>,
    /// The subkeys and values the key node counts.
    pub subkey_count: u32,
    pub value_count: u32,
    pub subkeys: Vec<RegSubkeyEntry>,
    pub values: Vec<RegValueEntry>,
    /// Subkey indexes and value lists that do not read, and counts that do
    /// not match.
    pub problems: Vec<String>,
}

type Read<T> = std::result::Result<T, String>;

fn u16_at(bytes: &[u8], at: usize) -> Read<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("the cell ends before offset {at:#x}"))
}

fn u32_at(bytes: &[u8], at: usize) -> Read<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("the cell ends before offset {at:#x}"))
}

fn uint_at(bytes: &[u8], at: usize, size: usize) -> Read<u64> {
    let field = bytes
        .get(at..at + size)
        .ok_or_else(|| format!("the cell ends before offset {at:#x}"))?;
    let mut value = [0u8; 8];
    value[..size.min(8)].copy_from_slice(&field[..size.min(8)]);
    Ok(u64::from_le_bytes(value))
}

fn signature_text(signature: u16) -> String {
    let [a, b] = signature.to_le_bytes();
    if a.is_ascii_graphic() && b.is_ascii_graphic() {
        format!("'{}{}'", a as char, b as char)
    } else {
        format!("{signature:#06x}")
    }
}

/// A record's name: one byte per character when `compressed`, UTF-16
/// otherwise.
fn record_name(bytes: &[u8], at: usize, length: usize, compressed: bool) -> Read<String> {
    let name = bytes
        .get(at..at + length)
        .ok_or_else(|| format!("the name runs past the cell ({length:#x} bytes at {at:#x})"))?;
    Ok(if compressed {
        name.iter().map(|&byte| byte as char).collect()
    } else {
        utf16le_lossy(name)
    })
}

/// Whether two key or value names are the same name: the registry
/// compares them without case.
pub fn names_equal(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

/// The hash an `lh` index keeps of a name (`37 * hash + upcase(char)`),
/// for an ASCII name, whose upcasing is unambiguous.
fn name_hash(name: &str) -> Option<u32> {
    name.is_ascii().then(|| {
        name.bytes().fold(0u32, |hash, byte| {
            hash.wrapping_mul(37)
                .wrapping_add(byte.to_ascii_uppercase().into())
        })
    })
}

/// The components of a full registry path below `\REGISTRY`. Takes
/// `\REGISTRY\...` and the predefined keys' common names: `HKLM`
/// (`HKEY_LOCAL_MACHINE`), `HKU` (`HKEY_USERS`), `HKCR`
/// (`HKEY_CLASSES_ROOT`, the machine's classes), and `HKCC`
/// (`HKEY_CURRENT_CONFIG`).
pub fn registry_path_components(path: &str) -> Result<Vec<String>> {
    let mut parts = path.trim().split('\\').filter(|part| !part.is_empty());
    let Some(first) = parts.next() else {
        return Err(Error::InvalidArgument("an empty registry path".into()));
    };
    let root: &[&str] = match first.to_ascii_uppercase().as_str() {
        "REGISTRY" => &[],
        "HKLM" | "HKEY_LOCAL_MACHINE" => &["MACHINE"],
        "HKU" | "HKEY_USERS" => &["USER"],
        "HKCR" | "HKEY_CLASSES_ROOT" => &["MACHINE", "SOFTWARE", "Classes"],
        "HKCC" | "HKEY_CURRENT_CONFIG" => &[
            "MACHINE",
            "SYSTEM",
            "CurrentControlSet",
            "Hardware Profiles",
            "Current",
        ],
        "HKCU" | "HKEY_CURRENT_USER" => {
            return Err(Error::InvalidArgument(
                "HKCU is the key of whichever user a thread runs as; give that user's key, \
                 HKU\\<SID> (!reg hivelist lists the users' hives)"
                    .into(),
            ));
        }
        _ => {
            return Err(Error::InvalidArgument(format!(
                "{path} is not a full registry path; start it with \\REGISTRY, HKLM, HKU, \
                 HKCR, or HKCC"
            )));
        }
    };
    Ok(root
        .iter()
        .map(|part| part.to_string())
        .chain(parts.map(str::to_string))
        .collect())
}

/// Where the fields of the hive format's records are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CellLayout {
    node: NodeLayout,
    value: ValueLayout,
    /// `_CM_KEY_INDEX`.
    index: HeaderLayout,
    /// `_CM_INDEX`, an `lf` or `lh` index's entry.
    fast: FastEntryLayout,
    /// `_CM_BIG_DATA`.
    big: HeaderLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeLayout {
    signature: usize,
    flags: usize,
    last_write: usize,
    parent: usize,
    subkey_counts: usize,
    subkey_lists: usize,
    /// `ChildHiveReference`, which a link node holds in place of its
    /// subkey lists.
    child_cell: usize,
    child_hive: usize,
    child_hive_size: usize,
    value_count: usize,
    value_list: usize,
    name_length: usize,
    name: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValueLayout {
    signature: usize,
    name_length: usize,
    data_length: usize,
    data: usize,
    value_type: usize,
    flags: usize,
    name: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeaderLayout {
    signature: usize,
    count: usize,
    list: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FastEntryLayout {
    size: usize,
    cell: usize,
    hash: usize,
}

impl CellLayout {
    /// The offsets the 64-bit hive format puts the fields at.
    const FORMAT: Self = Self {
        node: NodeLayout {
            signature: 0,
            flags: 2,
            last_write: 4,
            parent: 0x10,
            subkey_counts: 0x14,
            subkey_lists: 0x1c,
            child_cell: 0x1c,
            child_hive: 0x24,
            child_hive_size: 8,
            value_count: 0x24,
            value_list: 0x28,
            name_length: 0x48,
            name: 0x4c,
        },
        value: ValueLayout {
            signature: 0,
            name_length: 2,
            data_length: 4,
            data: 8,
            value_type: 0xc,
            flags: 0x10,
            name: 0x14,
        },
        index: HeaderLayout {
            signature: 0,
            count: 2,
            list: 4,
        },
        fast: FastEntryLayout {
            size: 8,
            cell: 0,
            hash: 4,
        },
        big: HeaderLayout {
            signature: 0,
            count: 2,
            list: 4,
        },
    };

    /// The kernel's layouts of the records, field by field where its PDB
    /// has them.
    fn from_types(types: Types<'_>) -> Self {
        let layout = |name: &str| types.layout(name).ok();
        let at = |layout: &Option<Arc<TypeInfo>>, field: &str, fallback: usize| {
            layout
                .as_ref()
                .and_then(|layout| layout.field_offset(field).ok())
                .map_or(fallback, |offset| offset as usize)
        };
        let format = Self::FORMAT;
        let node = layout("_CM_KEY_NODE");
        let reference = layout("_CM_KEY_REFERENCE");
        let children = layout("_CHILD_LIST");
        let value = layout("_CM_KEY_VALUE");
        let index = layout("_CM_KEY_INDEX");
        let entry = layout("_CM_INDEX");
        let big = layout("_CM_BIG_DATA");
        let child = at(&node, "ChildHiveReference", format.node.child_cell);
        let value_list = at(&node, "ValueList", format.node.value_count);
        Self {
            node: NodeLayout {
                signature: at(&node, "Signature", format.node.signature),
                flags: at(&node, "Flags", format.node.flags),
                last_write: at(&node, "LastWriteTime", format.node.last_write),
                parent: at(&node, "Parent", format.node.parent),
                subkey_counts: at(&node, "SubKeyCounts", format.node.subkey_counts),
                subkey_lists: at(&node, "SubKeyLists", format.node.subkey_lists),
                child_cell: child + at(&reference, "KeyCell", 0),
                child_hive: child
                    + at(
                        &reference,
                        "KeyHive",
                        format.node.child_hive - format.node.child_cell,
                    ),
                child_hive_size: reference
                    .as_ref()
                    .and_then(|reference| reference.field("KeyHive").ok())
                    .map_or(format.node.child_hive_size, |field| field.size as usize),
                value_count: value_list + at(&children, "Count", 0),
                value_list: value_list + at(&children, "List", 4),
                name_length: at(&node, "NameLength", format.node.name_length),
                name: at(&node, "Name", format.node.name),
            },
            value: ValueLayout {
                signature: at(&value, "Signature", format.value.signature),
                name_length: at(&value, "NameLength", format.value.name_length),
                data_length: at(&value, "DataLength", format.value.data_length),
                data: at(&value, "Data", format.value.data),
                value_type: at(&value, "Type", format.value.value_type),
                flags: at(&value, "Flags", format.value.flags),
                name: at(&value, "Name", format.value.name),
            },
            index: HeaderLayout {
                signature: at(&index, "Signature", format.index.signature),
                count: at(&index, "Count", format.index.count),
                list: at(&index, "List", format.index.list),
            },
            fast: FastEntryLayout {
                size: entry.as_ref().map_or(format.fast.size, |entry| entry.size),
                cell: at(&entry, "Cell", format.fast.cell),
                hash: at(&entry, "HashKey", format.fast.hash),
            },
            big: HeaderLayout {
                signature: at(&big, "Signature", format.big.signature),
                count: at(&big, "Count", format.big.count),
                list: at(&big, "List", format.big.list),
            },
        }
    }
}

/// How an `_HMAP_ENTRY` names the memory of its block.
#[derive(Debug, Clone, Copy)]
enum MapEntryLayout {
    /// `PermanentBinAddress`, the bin's address with flags in its low bits,
    /// and `BlockOffset`, the block's offset in the bin (Windows 10 and
    /// later).
    Bin { bin_address: u64, block_offset: u64 },
    /// `BlockAddress`, the block's own address.
    Block { block_address: u64 },
}

/// Where the cell map's fields are, from the kernel's PDB.
#[derive(Debug, Clone, Copy)]
struct MapLayout {
    /// `_HMAP_DIRECTORY.Directory`, and the size of its pointers.
    directory: u64,
    pointer_size: usize,
    /// `_HMAP_TABLE.Table`.
    table: u64,
    entry_size: u64,
    entry: MapEntryLayout,
}

impl MapLayout {
    fn from_types(types: Types<'_>) -> Result<Self> {
        let directory = types.layout("_HMAP_DIRECTORY")?;
        let table = types.layout("_HMAP_TABLE")?;
        let entry = types.layout("_HMAP_ENTRY")?;
        let entry_layout = match entry.field_offset("PermanentBinAddress") {
            Ok(bin_address) => MapEntryLayout::Bin {
                bin_address,
                block_offset: entry.field_offset("BlockOffset")?,
            },
            Err(_) => MapEntryLayout::Block {
                block_address: entry.field_offset("BlockAddress")?,
            },
        };
        Ok(Self {
            directory: directory.field_offset("Directory")?,
            pointer_size: directory.pointer_size.into(),
            table: table.field_offset("Table")?,
            entry_size: entry.size as u64,
            entry: entry_layout,
        })
    }
}

/// A key node, decoded.
#[derive(Debug, Clone)]
struct Node {
    /// The node: the cell's data, after its size field.
    address: VirtAddr,
    flags: u16,
    last_write: u64,
    parent: u32,
    subkey_counts: [u32; 2],
    subkey_lists: [u32; 2],
    value_count: u32,
    value_list: u32,
    name: String,
    /// A link node's `ChildHiveReference`: the `_HHIVE` and the cell of
    /// the root it links to.
    child: Option<(VirtAddr, u32)>,
}

/// What a path resolved to.
struct Opened<'r> {
    hive: &'r Hive,
    cell: u32,
    node: Node,
    path: String,
    links: Vec<RegLink>,
}

/// Reads hives through the Registry process's address space.
struct Registry<'a> {
    memory: AddressSpace<'a, PhysMem>,
    cells: CellLayout,
    map: MapLayout,
    /// The readable hives.
    hives: Vec<Hive>,
    /// `_CMHIVE.Hive`: where the `_HHIVE` a link node points to sits in its
    /// `_CMHIVE`.
    hhive_offset: u64,
    /// The cell map tables read, by directory and index.
    tables: RefCell<HashMap<(VirtAddr, u32), VirtAddr>>,
}

/// Read the hive at `address`.
fn read_hive(types: Types<'_>, address: VirtAddr, master: bool) -> Result<Hive> {
    let cmhive = types.struct_at("_CMHIVE", address)?;
    let hive = cmhive.embedded("Hive")?.prefetch();
    let signature = hive.read_uint("Signature")?;
    if signature != HHIVE_SIGNATURE {
        return Err(Error::DebugInfo(format!(
            "not a hive: its signature is {signature:#x}, not {HHIVE_SIGNATURE:#x}"
        )));
    }
    let storage = hive.layout().field_offset("Storage")?;
    let dual = types.layout("_DUAL")?;
    let storage_at = |index: u64| -> Result<HiveStorage> {
        let dual = types.struct_with_layout(
            Arc::clone(&dual),
            hive.addr() + storage + index * dual.size as u64,
        );
        Ok(HiveStorage {
            length: dual.read_uint("Length")? as u32,
            map: dual.read_pointer("Map")?,
        })
    };
    let base_block = hive.read_pointer("BaseBlock")?;
    let base = types.struct_at("_HBASE_BLOCK", base_block)?;
    let text = |field: &str| {
        cmhive
            .unicode_string(field)
            .ok()
            .filter(|text| !text.is_empty())
    };
    Ok(Hive {
        address,
        master,
        mount: if master {
            Some("\\REGISTRY".to_string())
        } else {
            text("HiveRootPath")
        },
        file: text("FileUserName").or_else(|| text("FileFullPath")),
        base_block,
        base_block_name: base
            .read_field_bytes("FileName", 0x100)
            .ok()
            .map(|name| utf16le_nul_terminated(&name))
            .filter(|name| !name.is_empty()),
        root_cell: DiagnosticValue::from_result(base.read_uint("RootCell").map(|cell| cell as u32)),
        version: hive.read_uint("Version")? as u32,
        flags: hive.read_uint("HiveFlags")? as u32,
        flat: hive.read_bits("Flat")? != 0,
        stable: storage_at(0)?,
        volatile: storage_at(1)?,
    })
}

/// The hives on the list at `head`; `master` is the master hive's address.
fn read_hive_list(
    types: Types<'_>,
    memory: &AddressSpace<'_, PhysMem>,
    head: VirtAddr,
    master: Option<VirtAddr>,
) -> Result<HiveList> {
    let link = types.layout("_CMHIVE")?.field_offset("HiveList")?;
    let (addresses, termination) =
        bounded_record_list_walk(head, link, MAX_HIVES, |at| memory.read::<VirtAddr>(at));
    let hives = addresses
        .into_iter()
        .map(|address| {
            read_hive(types, address, master == Some(address))
                .map_err(|error| (address, error.to_string()))
        })
        .collect();
    Ok(HiveList {
        hives,
        stopped: termination.diagnostic(),
    })
}

impl<'a> Registry<'a> {
    fn new(types: Types<'_>, memory: AddressSpace<'a, PhysMem>, list: &HiveList) -> Result<Self> {
        Ok(Self {
            cells: CellLayout::from_types(types),
            map: MapLayout::from_types(types)?,
            hhive_offset: types.layout("_CMHIVE")?.field_offset("Hive")?,
            hives: list.hives.iter().flatten().cloned().collect(),
            memory,
            tables: RefCell::default(),
        })
    }

    fn hive(&self, address: VirtAddr) -> Result<&Hive> {
        self.hives
            .iter()
            .find(|hive| hive.address == address)
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "{address:#x} is not a readable hive on nt!CmpHiveListHead (!reg hivelist \
                     lists them)"
                ))
            })
    }

    fn master(&self) -> Result<&Hive> {
        self.hives.iter().find(|hive| hive.master).ok_or_else(|| {
            Error::DebugInfo("the master hive (nt!CmpMasterHive) does not read".into())
        })
    }

    fn root_cell(hive: &Hive) -> Result<u32> {
        match &hive.root_cell {
            DiagnosticValue::Available(cell) => Ok(*cell),
            DiagnosticValue::Unavailable(error) => Err(Error::DebugInfo(format!(
                "the root cell of hive {:#x} does not read: {error}",
                hive.address
            ))),
        }
    }

    /// The cell map table `directory` of the storage whose map is `map`.
    fn table(&self, map: VirtAddr, directory: u32) -> Read<VirtAddr> {
        if let Some(&table) = self.tables.borrow().get(&(map, directory)) {
            return Ok(table);
        }
        let at = map + self.map.directory + u64::from(directory) * self.map.pointer_size as u64;
        let mut bytes = [0u8; 8];
        self.memory
            .read_bytes(at, &mut bytes[..self.map.pointer_size])
            .map_err(|error| format!("cell map directory entry {directory} at {at:#x}: {error}"))?;
        let table = VirtAddr(u64::from_le_bytes(bytes));
        if table.is_zero() {
            return Err(format!("cell map directory entry {directory} is empty"));
        }
        self.tables.borrow_mut().insert((map, directory), table);
        Ok(table)
    }

    /// Where `cell` of `hive` is, through its cell map.
    fn locate(&self, hive: &Hive, cell: u32) -> Read<(VirtAddr, Option<CellMapPath>)> {
        if cell == HCELL_NIL {
            return Err("the nil cell (0xffffffff)".into());
        }
        let volatile = cell & HCELL_VOLATILE != 0;
        let offset = cell & !HCELL_VOLATILE;
        let (storage, kind) = if volatile {
            (hive.volatile, "volatile")
        } else {
            (hive.stable, "stable")
        };
        if offset >= storage.length {
            return Err(format!(
                "cell {cell:#x} is past the end of the hive's {kind} storage ({:#x} bytes)",
                storage.length
            ));
        }
        if hive.flat {
            if volatile {
                return Err(format!(
                    "cell {cell:#x} is volatile, and a flat hive has none"
                ));
            }
            return Ok((hive.base_block + HBLOCK_SIZE + u64::from(offset), None));
        }
        if storage.map.is_zero() {
            return Err(format!("the hive's {kind} storage has no cell map"));
        }
        let directory = (offset >> 21) & 0x3ff;
        let table = (offset >> 12) & 0x1ff;
        let within = offset & 0xfff;
        let table_address = self
            .table(storage.map, directory)
            .map_err(|error| format!("cell {cell:#x}: {kind} {error}"))?;
        let entry = table_address + self.map.table + u64::from(table) * self.map.entry_size;
        let read = |at: u64| -> Read<u64> {
            self.memory.read::<u64>(entry + at).map_err(|error| {
                format!("cell {cell:#x}: its cell map entry at {entry:#x}: {error}")
            })
        };
        let (base, block_offset) = match self.map.entry {
            MapEntryLayout::Bin {
                bin_address,
                block_offset,
            } => (read(bin_address)? & !HMAP_FLAGS, Some(block_offset)),
            MapEntryLayout::Block { block_address } => (read(block_address)? & !HMAP_FLAGS, None),
        };
        if base == 0 {
            return Err(format!(
                "cell {cell:#x}: block {:#x} of the {kind} storage is not mapped",
                offset & !0xfff
            ));
        }
        let block = VirtAddr(match block_offset {
            Some(at) => base + read(at)?,
            None => base,
        });
        Ok((
            block + u64::from(within),
            Some(CellMapPath {
                directory,
                table,
                offset: within,
                entry,
                block,
            }),
        ))
    }

    /// The data of the cell whose size field is at `address`.
    fn cell_at(&self, address: VirtAddr) -> Read<Vec<u8>> {
        let size = self
            .memory
            .read::<i32>(address)
            .map_err(|error| format!("the cell at {address:#x} is not in memory: {error}"))?;
        if size >= 0 {
            return Err(format!("the cell at {address:#x} is free (size {size:#x})"));
        }
        let size = size.unsigned_abs() as usize;
        if !(8..=MAX_CELL).contains(&size) {
            return Err(format!(
                "the cell at {address:#x} has no plausible size ({size:#x})"
            ));
        }
        let mut data = vec![0u8; size - CELL_HEADER as usize];
        self.memory
            .read_bytes(address + CELL_HEADER, &mut data)
            .map_err(|error| format!("the cell at {address:#x} is not in memory: {error}"))?;
        Ok(data)
    }

    /// The data of `cell` and its address.
    fn cell(&self, hive: &Hive, cell: u32) -> Read<(VirtAddr, Vec<u8>)> {
        let (address, _) = self.locate(hive, cell)?;
        let data = self
            .cell_at(address)
            .map_err(|error| format!("cell {cell:#x}: {error}"))?;
        Ok((address + CELL_HEADER, data))
    }

    fn decode_node(&self, address: VirtAddr, data: &[u8]) -> Read<Node> {
        let layout = &self.cells.node;
        let signature = u16_at(data, layout.signature)?;
        if signature != SIG_NK && signature != SIG_LK {
            return Err(format!(
                "{address:#x} is not a key node (signature {})",
                signature_text(signature)
            ));
        }
        let flags = u16_at(data, layout.flags)?;
        let name_length = u16_at(data, layout.name_length)?;
        let child = if flags & KEY_HIVE_EXIT != 0 {
            Some((
                VirtAddr(uint_at(data, layout.child_hive, layout.child_hive_size)?),
                u32_at(data, layout.child_cell)?,
            ))
        } else {
            None
        };
        let pair = |at: usize| -> Read<[u32; 2]> { Ok([u32_at(data, at)?, u32_at(data, at + 4)?]) };
        Ok(Node {
            address,
            flags,
            last_write: uint_at(data, layout.last_write, 8)?,
            parent: u32_at(data, layout.parent)?,
            subkey_counts: if child.is_some() {
                [0, 0]
            } else {
                pair(layout.subkey_counts)?
            },
            subkey_lists: pair(layout.subkey_lists)?,
            value_count: if child.is_some() {
                0
            } else {
                u32_at(data, layout.value_count)?
            },
            value_list: u32_at(data, layout.value_list)?,
            name: record_name(
                data,
                layout.name,
                name_length.into(),
                flags & KEY_COMP_NAME != 0,
            )?,
            child,
        })
    }

    fn node(&self, hive: &Hive, cell: u32) -> Read<Node> {
        let (address, data) = self.cell(hive, cell)?;
        self.decode_node(address, &data)
            .map_err(|error| format!("cell {cell:#x}: {error}"))
    }

    /// The node at `address`, the data of a cell.
    fn node_at(&self, address: VirtAddr) -> Read<Node> {
        let data = self.cell_at(address - CELL_HEADER)?;
        self.decode_node(address, &data)
    }

    /// The cells of a subkey index and, for an `lh` index, the hash of
    /// each one's name.
    fn index(
        &self,
        hive: &Hive,
        cell: u32,
        nested: bool,
        out: &mut Vec<(u32, Option<u32>)>,
        problems: &mut Vec<String>,
    ) {
        let data = match self.cell(hive, cell) {
            Ok((_, data)) => data,
            Err(error) => {
                problems.push(format!("subkey index: {error}"));
                return;
            }
        };
        let layout = self.cells.index;
        let (signature, count) =
            match (u16_at(&data, layout.signature), u16_at(&data, layout.count)) {
                (Ok(signature), Ok(count)) => (signature, usize::from(count)),
                (Err(error), _) | (_, Err(error)) => {
                    problems.push(format!("subkey index {cell:#x}: {error}"));
                    return;
                }
            };
        let stride = match signature {
            SIG_LF | SIG_LH => self.cells.fast.size,
            SIG_LI | SIG_RI => 4,
            other => {
                problems.push(format!(
                    "cell {cell:#x} is not a subkey index (signature {})",
                    signature_text(other)
                ));
                return;
            }
        };
        let fits = data.len().saturating_sub(layout.list) / stride.max(1);
        if count > fits {
            problems.push(format!(
                "subkey index {cell:#x} counts {count} entries, and its cell holds {fits}"
            ));
        }
        for entry in (0..count.min(fits)).map(|index| layout.list + index * stride) {
            if out.len() >= MAX_CHILDREN {
                problems.push(format!("stopped after {MAX_CHILDREN} subkeys"));
                return;
            }
            match signature {
                SIG_LF | SIG_LH => {
                    let child = u32_at(&data, entry + self.cells.fast.cell);
                    let hash = (signature == SIG_LH)
                        .then(|| u32_at(&data, entry + self.cells.fast.hash).ok())
                        .flatten();
                    if let Ok(child) = child {
                        out.push((child, hash));
                    }
                }
                SIG_LI => {
                    if let Ok(child) = u32_at(&data, entry) {
                        out.push((child, None));
                    }
                }
                _ if nested => {
                    problems.push(format!("root index {cell:#x} is inside another root index"));
                    return;
                }
                _ => {
                    if let Ok(leaf) = u32_at(&data, entry) {
                        self.index(hive, leaf, true, out, problems);
                    }
                }
            }
        }
    }

    /// The cells of a key's subkeys, stable then volatile, as the kernel
    /// enumerates them.
    fn subkey_cells(
        &self,
        hive: &Hive,
        node: &Node,
        problems: &mut Vec<String>,
    ) -> Vec<(u32, Option<u32>)> {
        let mut cells = Vec::new();
        for (count, list) in node.subkey_counts.into_iter().zip(node.subkey_lists) {
            let before = cells.len();
            let reported = problems.len();
            if count != 0 {
                self.index(hive, list, false, &mut cells, problems);
            }
            let found = cells.len() - before;
            if found != count as usize && problems.len() == reported {
                problems.push(format!(
                    "the key counts {count} subkeys in its {} storage, and its index lists {found}",
                    if list & HCELL_VOLATILE != 0 {
                        "volatile"
                    } else {
                        "stable"
                    }
                ));
            }
        }
        cells
    }

    /// The subkey of `node` named `name`.
    fn find_subkey(&self, hive: &Hive, node: &Node, name: &str) -> Result<Option<(u32, Node)>> {
        let mut problems = Vec::new();
        let hash = name_hash(name);
        for (cell, stored) in self.subkey_cells(hive, node, &mut problems) {
            if let (Some(hash), Some(stored)) = (hash, stored)
                && hash != stored
            {
                continue;
            }
            match self.node(hive, cell) {
                Ok(child) if names_equal(&child.name, name) => return Ok(Some((cell, child))),
                Ok(_) => {}
                Err(error) => problems.push(error),
            }
        }
        if problems.is_empty() {
            Ok(None)
        } else {
            Err(Error::DebugInfo(format!(
                "no readable subkey of {} is named {name}, and some do not read: {}",
                node.name,
                problems.join("; ")
            )))
        }
    }

    /// The cells of a key's values.
    fn value_cells(&self, hive: &Hive, node: &Node, problems: &mut Vec<String>) -> Vec<u32> {
        if node.value_count == 0 {
            return Vec::new();
        }
        let data = match self.cell(hive, node.value_list) {
            Ok((_, data)) => data,
            Err(error) => {
                problems.push(format!("value list: {error}"));
                return Vec::new();
            }
        };
        let count = (node.value_count as usize).min(MAX_CHILDREN);
        let fits = data.len() / 4;
        if count > fits {
            problems.push(format!(
                "the key counts {count} values, and its value list holds {fits}"
            ));
        }
        (0..count.min(fits))
            .filter_map(|index| u32_at(&data, index * 4).ok())
            .collect()
    }

    /// The bytes of a value's data stored in cell `data`: in it, or, for
    /// big data, in the segments its `db` record lists.
    fn value_data(&self, hive: &Hive, data: u32, length: usize) -> Read<(DataStorage, Vec<u8>)> {
        if length > MAX_VALUE_DATA {
            return Err(format!(
                "its {length:#x} bytes are more than the {MAX_VALUE_DATA:#x} read of a value"
            ));
        }
        let (_, cell) = self.cell(hive, data)?;
        let big = self.cells.big;
        if length > CM_KEY_VALUE_BIG
            && hive.version >= HSYS_WHISTLER_BETA1
            && u16_at(&cell, big.signature) == Ok(SIG_DB)
        {
            let count = usize::from(u16_at(&cell, big.count)?);
            let (_, list) = self.cell(hive, u32_at(&cell, big.list)?)?;
            if list.len() < count * 4 {
                return Err(format!(
                    "its big data record counts {count} segments, and its list holds {}",
                    list.len() / 4
                ));
            }
            let mut bytes = Vec::with_capacity(length);
            for index in 0..count {
                if bytes.len() >= length {
                    break;
                }
                let (_, segment) = self.cell(hive, u32_at(&list, index * 4)?)?;
                let wanted = (length - bytes.len()).min(CM_KEY_VALUE_BIG);
                let part = segment.get(..wanted).ok_or_else(|| {
                    format!(
                        "big data segment {index} holds {:#x} bytes, not {wanted:#x}",
                        segment.len()
                    )
                })?;
                bytes.extend_from_slice(part);
            }
            if bytes.len() < length {
                return Err(format!(
                    "its {count} big data segments hold {:#x} of its {length:#x} bytes",
                    bytes.len()
                ));
            }
            return Ok((DataStorage::Big, bytes));
        }
        let bytes = cell.get(..length).ok_or_else(|| {
            format!(
                "its data cell holds {:#x} bytes, not {length:#x}",
                cell.len()
            )
        })?;
        Ok((DataStorage::Cell, bytes.to_vec()))
    }

    fn value(&self, hive: &Hive, cell: u32) -> Read<RegValue> {
        let (address, data) = self.cell(hive, cell)?;
        let layout = &self.cells.value;
        let signature = u16_at(&data, layout.signature)?;
        if signature != SIG_VK {
            return Err(format!(
                "cell {cell:#x} is not a value (signature {})",
                signature_text(signature)
            ));
        }
        let flags = u16_at(&data, layout.flags)?;
        let name = record_name(
            &data,
            layout.name,
            u16_at(&data, layout.name_length)?.into(),
            flags & VALUE_COMP_NAME != 0,
        )?;
        let raw_length = u32_at(&data, layout.data_length)?;
        let value_type = u32_at(&data, layout.value_type)?;
        let (storage, data) = if raw_length & CM_KEY_VALUE_SPECIAL_SIZE != 0 {
            let length = (raw_length & !CM_KEY_VALUE_SPECIAL_SIZE) as usize;
            let inline = data
                .get(layout.data..layout.data + 4)
                .ok_or_else(|| "the value record ends before its data".to_string())?;
            let bytes = match inline.get(..length) {
                Some(bytes) => DiagnosticValue::Available(bytes.to_vec()),
                None => DiagnosticValue::unavailable(format!(
                    "its {length:#x} bytes are more than a value record holds"
                )),
            };
            (DataStorage::Inline, bytes)
        } else if raw_length == 0 {
            (DataStorage::Cell, DiagnosticValue::Available(Vec::new()))
        } else {
            let length = raw_length as usize;
            let big = length > CM_KEY_VALUE_BIG && hive.version >= HSYS_WHISTLER_BETA1;
            match self.value_data(hive, u32_at(&data, layout.data)?, length) {
                Ok((storage, bytes)) => (storage, DiagnosticValue::Available(bytes)),
                Err(error) => (
                    if big {
                        DataStorage::Big
                    } else {
                        DataStorage::Cell
                    },
                    DiagnosticValue::unavailable(error),
                ),
            }
        };
        Ok(RegValue {
            name,
            cell,
            node: address,
            value_type,
            length: raw_length & !CM_KEY_VALUE_SPECIAL_SIZE,
            storage,
            data,
        })
    }

    /// The target of a symbolic link key: its `SymbolicLinkValue`.
    fn link_target(&self, hive: &Hive, node: &Node, path: &str) -> Result<String> {
        let mut problems = Vec::new();
        for cell in self.value_cells(hive, node, &mut problems) {
            match self.value(hive, cell) {
                Ok(value) if names_equal(&value.name, SYMBOLIC_LINK_VALUE) => {
                    return match value.data {
                        DiagnosticValue::Available(bytes) => Ok(utf16le_nul_terminated(&bytes)),
                        DiagnosticValue::Unavailable(error) => Err(Error::DebugInfo(format!(
                            "{path} is a symbolic link, and its {SYMBOLIC_LINK_VALUE} does not \
                             read: {error}"
                        ))),
                    };
                }
                Ok(_) => {}
                Err(error) => problems.push(error),
            }
        }
        Err(Error::DebugInfo(format!(
            "{path} is a symbolic link without a readable {SYMBOLIC_LINK_VALUE}{}",
            if problems.is_empty() {
                String::new()
            } else {
                format!(": {}", problems.join("; "))
            }
        )))
    }

    /// The hive whose `_HHIVE` is at `hhive`.
    fn hive_of(&self, hhive: VirtAddr) -> Result<&Hive> {
        self.hive(hhive - self.hhive_offset)
    }

    /// Resolve a full path to its key.
    fn open(&self, path: &str) -> Result<Opened<'_>> {
        let mut components = registry_path_components(path)?;
        let mut links = Vec::new();
        for _ in 0..=MAX_REPARSE {
            let master = self.master()?;
            let mut hive = master;
            let mut cell = Self::root_cell(master)?;
            let mut node = self.node(hive, cell).map_err(Error::DebugInfo)?;
            let mut current = "\\REGISTRY".to_string();
            let mut index = 0;
            let reparsed = loop {
                if let Some((hhive, root)) = node.child {
                    hive = self.hive_of(hhive)?;
                    cell = root;
                    node = self.node(hive, cell).map_err(Error::DebugInfo)?;
                }
                if node.flags & KEY_SYM_LINK != 0 {
                    let target = self.link_target(hive, &node, &current)?;
                    let mut next = registry_path_components(&target)?;
                    next.extend(components.drain(index..));
                    links.push(RegLink {
                        from: current,
                        to: target,
                    });
                    break next;
                }
                let Some(name) = components.get(index) else {
                    return Ok(Opened {
                        hive,
                        cell,
                        node,
                        path: current,
                        links,
                    });
                };
                match self.find_subkey(hive, &node, name)? {
                    Some((child, child_node)) => {
                        current = format!("{current}\\{}", child_node.name);
                        cell = child;
                        node = child_node;
                    }
                    None => {
                        // A hive mounted where no link node leads to it,
                        // such as an application hive under \REGISTRY\A.
                        let wanted = format!("{current}\\{name}");
                        let Some(mounted) = self.hives.iter().find(|hive| {
                            hive.mount
                                .as_deref()
                                .is_some_and(|mount| names_equal(mount, &wanted))
                        }) else {
                            return Err(Error::DebugInfo(format!(
                                "{current} has no subkey {name}"
                            )));
                        };
                        hive = mounted;
                        cell = Self::root_cell(hive)?;
                        node = self.node(hive, cell).map_err(Error::DebugInfo)?;
                        current = mounted.mount.clone().unwrap_or(wanted);
                    }
                }
                index += 1;
            };
            components = reparsed;
        }
        Err(Error::DebugInfo(format!(
            "{path} goes through more than {MAX_REPARSE} symbolic links"
        )))
    }

    /// The path of a key, from its parents up to its hive's root.
    fn path_of(&self, hive: &Hive, node: &Node) -> Read<String> {
        let mut names = Vec::new();
        let mut current = node.clone();
        for _ in 0..MAX_DEPTH {
            if current.flags & KEY_HIVE_ENTRY != 0 {
                let mount = hive
                    .mount
                    .clone()
                    .ok_or_else(|| "its hive has no mount point".to_string())?;
                names.reverse();
                return Ok(std::iter::once(mount)
                    .chain(names)
                    .collect::<Vec<_>>()
                    .join("\\"));
            }
            names.push(current.name.clone());
            current = self.node(hive, current.parent)?;
        }
        Err(format!(
            "its hive's root is more than {MAX_DEPTH} parents up"
        ))
    }

    /// A key with its subkeys and values.
    fn key(
        &self,
        hive: &Hive,
        cell: Option<u32>,
        node: Node,
        path: String,
        links: Vec<RegLink>,
    ) -> RegKey {
        let mut problems = Vec::new();
        let subkeys = self
            .subkey_cells(hive, &node, &mut problems)
            .into_iter()
            .map(|(child, _)| {
                let child_node = self.node(hive, child).map_err(|error| (child, error))?;
                Ok(RegSubkey {
                    name: child_node.name,
                    cell: child,
                    node: child_node.address,
                    flags: child_node.flags,
                    last_write: child_node.last_write,
                    subkeys: child_node.subkey_counts[0]
                        .saturating_add(child_node.subkey_counts[1]),
                    values: child_node.value_count,
                })
            })
            .collect();
        let values = self
            .value_cells(hive, &node, &mut problems)
            .into_iter()
            .map(|value| self.value(hive, value).map_err(|error| (value, error)))
            .collect();
        RegKey {
            path,
            hive: hive.address,
            cell,
            node: node.address,
            name: node.name,
            flags: node.flags,
            last_write: node.last_write,
            links,
            subkey_count: node.subkey_counts[0].saturating_add(node.subkey_counts[1]),
            value_count: node.value_count,
            subkeys,
            values,
            problems,
        }
    }

    fn query(&self, path: &str) -> Result<RegKey> {
        let opened = self.open(path)?;
        Ok(self.key(
            opened.hive,
            Some(opened.cell),
            opened.node,
            opened.path,
            opened.links,
        ))
    }

    fn key_at(&self, hive: VirtAddr, node: VirtAddr) -> Result<RegKey> {
        let hive = self.hive(hive)?;
        let decoded = self.node_at(node).map_err(Error::DebugInfo)?;
        let mut key = self.key(hive, None, decoded.clone(), String::new(), Vec::new());
        key.path = match self.path_of(hive, &decoded) {
            Ok(path) => path,
            Err(error) => {
                key.problems
                    .push(format!("its path does not read: {error}"));
                decoded.name
            }
        };
        Ok(key)
    }

    fn cell_location(&self, hive: VirtAddr, cell: u32) -> Result<CellLocation> {
        let hive = self.hive(hive)?;
        let (address, map) = self.locate(hive, cell).map_err(Error::DebugInfo)?;
        Ok(CellLocation {
            hive: hive.address,
            cell,
            volatile: cell & HCELL_VOLATILE != 0,
            map,
            address,
            size: DiagnosticValue::from_result(self.memory.read::<i32>(address)),
        })
    }

    fn subkey_names(&self, path: &str) -> Result<Vec<String>> {
        let opened = self.open(path)?;
        let mut problems = Vec::new();
        Ok(self
            .subkey_cells(opened.hive, &opened.node, &mut problems)
            .into_iter()
            .filter_map(|(cell, _)| self.node(opened.hive, cell).ok())
            .map(|node| node.name)
            .collect())
    }
}

impl Target {
    fn kernel_global(&self, name: &str) -> Result<VirtAddr> {
        Ok(self.guest()?.ntoskrnl.symbol(name)?.address())
    }

    /// The hives on `nt!CmpHiveListHead`, and a reader of them in the
    /// address space of the Registry process.
    fn registry(&self) -> Result<(HiveList, Registry<'_>)> {
        let guest = self.guest()?;
        let kernel = self.kernel_address_space();
        let pointer = |name: &str| {
            self.kernel_global(name)
                .ok()
                .and_then(|at| kernel.read::<VirtAddr>(at).ok())
                .filter(|pointer| !pointer.is_zero())
        };
        let head = self.kernel_global("CmpHiveListHead")?;
        let master = pointer("CmpMasterHive");
        // `nt!CmpRegistryProcess` is a kernel handle to the minimal process
        // the kernel names `Registry`; a user-mode image's name has an
        // extension. Without one (before Windows 10), every hive is in
        // pool, which the kernel's page tables map.
        let dtb = guest
            .enumerate_processes()
            .ok()
            .and_then(|processes| {
                processes
                    .into_iter()
                    .find(|process| process.name == REGISTRY_PROCESS)
            })
            .map(|process| process.dtb)
            .filter(|&dtb| dtb != 0)
            .unwrap_or_else(|| self.kernel_dtb());
        let types = self.types_in(dtb);
        let memory = self.address_space(dtb);
        let list = read_hive_list(types, &memory, head, master)?;
        let registry = Registry::new(types, memory, &list)?;
        Ok((list, registry))
    }

    /// The loaded hives (`!reg hivelist`).
    pub fn registry_hives(&self) -> Result<HiveList> {
        Ok(self.registry()?.0)
    }

    /// The key at a full path, such as
    /// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip` (`!reg querykey`).
    pub fn registry_key(&self, path: &str) -> Result<RegKey> {
        self.registry()?.1.query(path)
    }

    /// The key whose node (`_CM_KEY_NODE`) is at `node` in the hive at
    /// `hive` (`!reg keyinfo`).
    pub fn registry_key_at(&self, hive: VirtAddr, node: VirtAddr) -> Result<RegKey> {
        self.registry()?.1.key_at(hive, node)
    }

    /// Where `cell` of the hive at `hive` is (`!reg cellindex`).
    pub fn registry_cell(&self, hive: VirtAddr, cell: u32) -> Result<CellLocation> {
        self.registry()?.1.cell_location(hive, cell)
    }

    /// The names of the subkeys of the key at `path` that read.
    pub fn registry_subkey_names(&self, path: &str) -> Result<Vec<String>> {
        self.registry()?.1.subkey_names(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{FieldInfo, ParsedType};
    use crate::session::{Session, session_over_memory};

    const BASE: u64 = 0x10000;
    const SIZE: usize = 0xa000;
    const HEAD: u64 = BASE;
    const MASTER: u64 = BASE + 0x100;
    const SYSTEM: u64 = BASE + 0x200;
    const MASTER_BASE_BLOCK: u64 = BASE + 0x300;
    const SYSTEM_BASE_BLOCK: u64 = BASE + 0x380;
    const MASTER_DIRECTORY: u64 = BASE + 0x400;
    const SYSTEM_DIRECTORIES: [u64; 2] = [BASE + 0x420, BASE + 0x430];
    const MASTER_TABLE: u64 = BASE + 0x500;
    const SYSTEM_TABLES: [u64; 2] = [BASE + 0x600, BASE + 0x800];
    const MOUNT: u64 = BASE + 0x900;
    const MASTER_BIN: u64 = BASE + 0x2000;
    const VOLATILE_BIN: u64 = BASE + 0x3000;
    /// The SYSTEM hive's stable bins, apart in memory: one block, five
    /// blocks, and one block the dump does not hold.
    const SYSTEM_BINS: [u64; 3] = [BASE + 0x1000, BASE + 0x5000, 0xdead_0000];
    const MOUNT_PATH: &str = "\\REGISTRY\\MACHINE\\SYSTEM";
    const LINK_TARGET: &str = "\\Registry\\Machine\\SYSTEM\\ControlSet001";
    const LAST_WRITE: u64 = 0x01dc_88ae_6ff6_dbd1;

    fn field(offset: u32, size: u64, type_data: ParsedType) -> FieldInfo {
        FieldInfo {
            offset,
            size,
            type_data,
        }
    }

    fn scalar(offset: u32, size: u64) -> FieldInfo {
        field(
            offset,
            size,
            ParsedType::Primitive(format!("u{}", size * 8)),
        )
    }

    fn pointer(offset: u32) -> FieldInfo {
        field(
            offset,
            8,
            ParsedType::Pointer(Box::new(ParsedType::Primitive("void".into()))),
        )
    }

    fn nested(offset: u32, size: u64, name: &str) -> FieldInfo {
        field(offset, size, ParsedType::Struct(name.into()))
    }

    fn array(offset: u32, size: u64, element: ParsedType, count: u32) -> FieldInfo {
        field(offset, size, ParsedType::Array(Box::new(element), count))
    }

    fn layout(name: &str, size: usize, fields: Vec<(&str, FieldInfo)>) -> TypeInfo {
        TypeInfo {
            name: name.into(),
            size,
            fields: fields
                .into_iter()
                .map(|(name, field)| (name.to_string(), field))
                .collect(),
            pointer_size: 8,
        }
    }

    /// The kernel's hive layouts, at offsets of their own: the reader finds
    /// every field by name. The records in the cells have no layouts here,
    /// so they decode at the hive format's offsets.
    fn layouts() -> Vec<TypeInfo> {
        vec![
            layout(
                "_CMHIVE",
                0xc0,
                vec![
                    ("Hive", nested(0, 0x80, "_HHIVE")),
                    ("HiveList", nested(0x80, 0x10, "_LIST_ENTRY")),
                    ("FileFullPath", nested(0x90, 0x10, "_UNICODE_STRING")),
                    ("FileUserName", nested(0xa0, 0x10, "_UNICODE_STRING")),
                    ("HiveRootPath", nested(0xb0, 0x10, "_UNICODE_STRING")),
                ],
            ),
            layout(
                "_HHIVE",
                0x80,
                vec![
                    ("Signature", scalar(0, 4)),
                    ("BaseBlock", pointer(8)),
                    (
                        "Flat",
                        field(
                            0x10,
                            1,
                            ParsedType::Bitfield {
                                underlying: Box::new(ParsedType::Primitive("UCHAR".into())),
                                pos: 0,
                                len: 1,
                            },
                        ),
                    ),
                    ("Version", scalar(0x14, 4)),
                    ("HiveFlags", scalar(0x18, 4)),
                    (
                        "Storage",
                        array(0x20, 0x30, ParsedType::Struct("_DUAL".into()), 2),
                    ),
                ],
            ),
            layout(
                "_DUAL",
                0x18,
                vec![("Length", scalar(0, 4)), ("Map", pointer(8))],
            ),
            layout(
                "_HMAP_DIRECTORY",
                0x2000,
                vec![(
                    "Directory",
                    array(
                        0,
                        0x2000,
                        ParsedType::Pointer(Box::new(ParsedType::Struct("_HMAP_TABLE".into()))),
                        1024,
                    ),
                )],
            ),
            layout(
                "_HMAP_TABLE",
                0x3000,
                vec![(
                    "Table",
                    array(0, 0x3000, ParsedType::Struct("_HMAP_ENTRY".into()), 512),
                )],
            ),
            layout(
                "_HMAP_ENTRY",
                0x18,
                vec![
                    ("BlockOffset", scalar(0, 8)),
                    ("PermanentBinAddress", scalar(8, 8)),
                    ("MemAlloc", scalar(0x10, 4)),
                ],
            ),
            layout(
                "_HBASE_BLOCK",
                0x70,
                vec![
                    ("RootCell", scalar(0x24, 4)),
                    (
                        "FileName",
                        array(0x30, 0x40, ParsedType::Primitive("UCHAR".into()), 64),
                    ),
                ],
            ),
            layout(
                "_UNICODE_STRING",
                0x10,
                vec![
                    ("Length", scalar(0, 2)),
                    ("MaximumLength", scalar(2, 2)),
                    ("Buffer", pointer(8)),
                ],
            ),
        ]
    }

    fn put(memory: &mut [u8], address: u64, bytes: &[u8]) {
        let at = (address - BASE) as usize;
        memory[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u64(memory: &mut [u8], address: u64, value: u64) {
        put(memory, address, &value.to_le_bytes());
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A storage of a test hive: its bins end to end, by hive offset.
    #[derive(Default)]
    struct Storage {
        bytes: Vec<u8>,
        /// Each bin's offset and size, and where its next cell goes.
        bins: Vec<(u32, u32, u32)>,
    }

    impl Storage {
        fn bin(&mut self, size: u32) -> usize {
            let start = self.bytes.len() as u32;
            self.bytes.resize((start + size) as usize, 0);
            self.bytes[start as usize..start as usize + 4].copy_from_slice(b"hbin");
            self.bins.push((start, size, start + 0x20));
            self.bins.len() - 1
        }

        /// A cell in use holding `data`, in bin `bin`: its offset.
        fn cell(&mut self, bin: usize, data: &[u8]) -> u32 {
            let size = (4 + data.len() as u32).next_multiple_of(8);
            let (start, length, next) = self.bins[bin];
            assert!(
                next + size <= start + length,
                "the cell does not fit its bin"
            );
            let at = next as usize;
            self.bytes[at..at + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
            self.bytes[at + 4..at + 4 + data.len()].copy_from_slice(data);
            self.bins[bin].2 = next + size;
            next
        }

        /// Set the `u32` at `at` in the data of `cell`.
        fn patch(&mut self, cell: u32, at: usize, value: u32) {
            let at = (cell & !HCELL_VOLATILE) as usize + 4 + at;
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn length(&self) -> u32 {
            self.bytes.len() as u32
        }

        /// Put the bins at `addresses`, those in the dump, and map each
        /// block in `table`, the cell map's only table.
        fn place(&self, memory: &mut [u8], addresses: &[u64], directory: u64, table: u64) {
            put_u64(memory, directory, table);
            for (&(start, size, _), &address) in self.bins.iter().zip(addresses) {
                if address >= BASE && address < BASE + SIZE as u64 {
                    put(
                        memory,
                        address,
                        &self.bytes[start as usize..(start + size) as usize],
                    );
                }
                for block in 0..size / 0x1000 {
                    let entry = table + u64::from(start / 0x1000 + block) * 0x18;
                    put_u64(memory, entry, u64::from(block) * 0x1000);
                    // The low bits hold flags.
                    put_u64(memory, entry + 8, address | 1);
                }
            }
        }
    }

    fn key_node(name: &str, flags: u16, subkeys: [(u32, u32); 2], values: (u32, u32)) -> Vec<u8> {
        let mut data = vec![0u8; 0x4c];
        data[0..2].copy_from_slice(b"nk");
        data[2..4].copy_from_slice(&(flags | KEY_COMP_NAME).to_le_bytes());
        data[4..12].copy_from_slice(&LAST_WRITE.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&HCELL_NIL.to_le_bytes());
        for (index, (count, list)) in subkeys.into_iter().enumerate() {
            data[0x14 + 4 * index..0x18 + 4 * index].copy_from_slice(&count.to_le_bytes());
            data[0x1c + 4 * index..0x20 + 4 * index].copy_from_slice(&list.to_le_bytes());
        }
        data[0x24..0x28].copy_from_slice(&values.0.to_le_bytes());
        data[0x28..0x2c].copy_from_slice(&values.1.to_le_bytes());
        data[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name.as_bytes());
        data
    }

    /// A link node in the master hive to the root of the hive whose
    /// `_HHIVE` is at `hive`.
    fn link_node(name: &str, hive: u64, root: u32) -> Vec<u8> {
        let mut data = key_node(name, KEY_HIVE_EXIT, [(0, HCELL_NIL); 2], (0, HCELL_NIL));
        data[0..2].copy_from_slice(b"lk");
        data[0x1c..0x20].copy_from_slice(&root.to_le_bytes());
        data[0x24..0x2c].copy_from_slice(&hive.to_le_bytes());
        data
    }

    fn value_record(name: &str, value_type: u32, length: u32, data: u32) -> Vec<u8> {
        let mut record = vec![0u8; 0x14];
        record[0..2].copy_from_slice(b"vk");
        record[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        record[4..8].copy_from_slice(&length.to_le_bytes());
        record[8..12].copy_from_slice(&data.to_le_bytes());
        record[0xc..0x10].copy_from_slice(&value_type.to_le_bytes());
        record[0x10..0x12].copy_from_slice(&VALUE_COMP_NAME.to_le_bytes());
        record.extend_from_slice(name.as_bytes());
        record
    }

    /// An `lf` or `lh` index of `(cell, name)` entries, with each name's
    /// hash for `lh`, or an `li` or `ri` index of cells.
    fn index(signature: &[u8; 2], entries: &[(u32, &str)]) -> Vec<u8> {
        let mut data = signature.to_vec();
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for &(cell, name) in entries {
            data.extend_from_slice(&cell.to_le_bytes());
            match signature {
                b"lh" => data.extend_from_slice(&name_hash(name).unwrap().to_le_bytes()),
                b"lf" => {
                    let mut hint = [0u8; 4];
                    for (slot, byte) in hint.iter_mut().zip(name.bytes()) {
                        *slot = byte;
                    }
                    data.extend_from_slice(&hint);
                }
                _ => {}
            }
        }
        data
    }

    fn cells(cells: &[u32]) -> Vec<u8> {
        cells.iter().flat_map(|cell| cell.to_le_bytes()).collect()
    }

    /// The big value's data: more than one cell holds.
    fn blob() -> Vec<u8> {
        (0..CM_KEY_VALUE_BIG + 0x10)
            .map(|index| (index % 251) as u8)
            .collect()
    }

    /// Cells of the test hives the tests look for.
    struct Fixture {
        system_root: u32,
        services: u32,
        qword_data: u32,
        current_control_set: u32,
    }

    fn put_hive(
        memory: &mut [u8],
        address: u64,
        base_block: u64,
        root: u32,
        storage: [(u32, u64); 2],
    ) {
        put(memory, address, &(HHIVE_SIGNATURE as u32).to_le_bytes());
        put_u64(memory, address + 8, base_block);
        put(memory, address + 0x14, &6u32.to_le_bytes());
        for (index, (length, map)) in storage.into_iter().enumerate() {
            let dual = address + 0x20 + 0x18 * index as u64;
            put(memory, dual, &length.to_le_bytes());
            put_u64(memory, dual + 8, map);
        }
        put(memory, base_block + 0x24, &root.to_le_bytes());
    }

    /// A master hive whose `\REGISTRY\MACHINE` links to a SYSTEM hive:
    /// a root with an `ri` index of an `lh` and an `li` leaf and a volatile
    /// `lf` index of `CurrentControlSet`, a symbolic link to
    /// `ControlSet001`, whose `Services` key has a value of each kind and a
    /// subkey in a bin the dump does not hold.
    fn registry_memory() -> (Vec<u8>, Fixture) {
        let mut memory = vec![0u8; SIZE];
        let mut stable = Storage::default();
        let small = stable.bin(0x1000);
        let large = stable.bin(0x5000);
        let absent = stable.bin(0x1000);

        // Services' values.
        let start = stable.cell(small, &value_record("Start", REG_DWORD, 0x8000_0004, 2));
        let image_data = stable.cell(small, &utf16("%SystemRoot%\\x.sys\0"));
        let image = stable.cell(
            small,
            &value_record("ImagePath", REG_EXPAND_SZ, 38, image_data),
        );
        let multi_data = stable.cell(small, &utf16("a\0bc\0\0ignored\0"));
        let multi = stable.cell(
            small,
            &value_record("DependOnService", REG_MULTI_SZ, 28, multi_data),
        );
        let blob = blob();
        let first = stable.cell(large, &blob[..CM_KEY_VALUE_BIG]);
        let second = stable.cell(small, &blob[CM_KEY_VALUE_BIG..]);
        let segments = stable.cell(small, &cells(&[first, second]));
        let mut big = b"db".to_vec();
        big.extend_from_slice(&2u16.to_le_bytes());
        big.extend_from_slice(&segments.to_le_bytes());
        let big = stable.cell(small, &big);
        let blob_value = stable.cell(
            small,
            &value_record("Blob", REG_BINARY, blob.len() as u32, big),
        );
        // In the big bin's last block, mapped at its offset in the bin.
        let qword_data = stable.cell(large, &0x0123_4567_89ab_cdefu64.to_le_bytes());
        let qword = stable.cell(small, &value_record("Q", REG_QWORD, 8, qword_data));
        let default_data = stable.cell(small, &utf16("dflt\0"));
        let default = stable.cell(small, &value_record("", REG_SZ, 10, default_data));
        let big_endian = stable.cell(
            small,
            &value_record("BE", REG_DWORD_BIG_ENDIAN, 0x8000_0004, 0x1234_5678),
        );
        let values = [start, image, multi, blob_value, qword, default, big_endian];
        let value_list = stable.cell(small, &cells(&values));

        let gone = stable.cell(
            absent,
            &key_node("Gone", 0, [(0, HCELL_NIL); 2], (0, HCELL_NIL)),
        );
        let services_index = stable.cell(small, &index(b"lh", &[(gone, "Gone")]));
        let services = stable.cell(
            small,
            &key_node(
                "Services",
                0,
                [(1, services_index), (0, HCELL_NIL)],
                (values.len() as u32, value_list),
            ),
        );
        let control_set_index = stable.cell(small, &index(b"lh", &[(services, "Services")]));
        let control_set = stable.cell(
            small,
            &key_node(
                "ControlSet001",
                0,
                [(1, control_set_index), (0, HCELL_NIL)],
                (0, HCELL_NIL),
            ),
        );
        let select = stable.cell(
            small,
            &key_node("Select", 0, [(0, HCELL_NIL); 2], (0, HCELL_NIL)),
        );
        let setup = stable.cell(
            small,
            &key_node("Setup", 0, [(0, HCELL_NIL); 2], (0, HCELL_NIL)),
        );
        let hashed = stable.cell(
            small,
            &index(b"lh", &[(control_set, "ControlSet001"), (select, "Select")]),
        );
        let leaf = stable.cell(small, &index(b"li", &[(setup, "")]));
        let root_index = stable.cell(small, &index(b"ri", &[(hashed, ""), (leaf, "")]));

        let mut volatile = Storage::default();
        let bin = volatile.bin(0x1000);
        let link_data = volatile.cell(bin, &utf16(LINK_TARGET)) | HCELL_VOLATILE;
        let link_value = volatile.cell(
            bin,
            &value_record(
                SYMBOLIC_LINK_VALUE,
                REG_LINK,
                (LINK_TARGET.len() * 2) as u32,
                link_data,
            ),
        ) | HCELL_VOLATILE;
        let link_values = volatile.cell(bin, &cells(&[link_value])) | HCELL_VOLATILE;
        let current_control_set = volatile.cell(
            bin,
            &key_node(
                "CurrentControlSet",
                KEY_SYM_LINK | KEY_VOLATILE,
                [(0, HCELL_NIL); 2],
                (1, link_values),
            ),
        ) | HCELL_VOLATILE;
        let volatile_index = volatile.cell(
            bin,
            &index(b"lf", &[(current_control_set, "CurrentControlSet")]),
        ) | HCELL_VOLATILE;

        let system_root = stable.cell(
            small,
            &key_node(
                "ROOT",
                KEY_HIVE_ENTRY | KEY_NO_DELETE,
                [(3, root_index), (1, volatile_index)],
                (0, HCELL_NIL),
            ),
        );
        for (child, parent) in [
            (control_set, system_root),
            (select, system_root),
            (setup, system_root),
            (services, control_set),
            (gone, services),
        ] {
            stable.patch(child, 0x10, parent);
        }
        volatile.patch(current_control_set, 0x10, system_root);

        // The master hive: \REGISTRY\MACHINE\SYSTEM links to the root.
        let mut master = Storage::default();
        let bin = master.bin(0x1000);
        let link = master.cell(bin, &link_node("SYSTEM", SYSTEM, system_root));
        let machine_index = master.cell(bin, &index(b"li", &[(link, "")]));
        let machine = master.cell(
            bin,
            &key_node(
                "MACHINE",
                0,
                [(1, machine_index), (0, HCELL_NIL)],
                (0, HCELL_NIL),
            ),
        );
        let registry_index = master.cell(bin, &index(b"lf", &[(machine, "MACHINE")]));
        let registry_root = master.cell(
            bin,
            &key_node(
                "REGISTRY",
                KEY_HIVE_ENTRY | KEY_NO_DELETE,
                [(1, registry_index), (0, HCELL_NIL)],
                (0, HCELL_NIL),
            ),
        );

        master.place(&mut memory, &[MASTER_BIN], MASTER_DIRECTORY, MASTER_TABLE);
        stable.place(
            &mut memory,
            &SYSTEM_BINS,
            SYSTEM_DIRECTORIES[0],
            SYSTEM_TABLES[0],
        );
        // The volatile storage's second block is not mapped.
        volatile.place(
            &mut memory,
            &[VOLATILE_BIN],
            SYSTEM_DIRECTORIES[1],
            SYSTEM_TABLES[1],
        );
        put_hive(
            &mut memory,
            MASTER,
            MASTER_BASE_BLOCK,
            registry_root,
            [(master.length(), MASTER_DIRECTORY), (0, 0)],
        );
        put_hive(
            &mut memory,
            SYSTEM,
            SYSTEM_BASE_BLOCK,
            system_root,
            [
                (stable.length(), SYSTEM_DIRECTORIES[0]),
                (volatile.length() + 0x1000, SYSTEM_DIRECTORIES[1]),
            ],
        );
        let mount = utf16(MOUNT_PATH);
        put(&mut memory, MOUNT, &mount);
        put(
            &mut memory,
            SYSTEM + 0xb0,
            &(mount.len() as u16).to_le_bytes(),
        );
        put(
            &mut memory,
            SYSTEM + 0xb2,
            &(mount.len() as u16).to_le_bytes(),
        );
        put_u64(&mut memory, SYSTEM + 0xb8, MOUNT);
        // nt!CmpHiveListHead -> master -> SYSTEM -> head.
        for (link, next, previous) in [
            (HEAD, MASTER + 0x80, SYSTEM + 0x80),
            (MASTER + 0x80, SYSTEM + 0x80, HEAD),
            (SYSTEM + 0x80, HEAD, MASTER + 0x80),
        ] {
            put_u64(&mut memory, link, next);
            put_u64(&mut memory, link + 8, previous);
        }
        (
            memory,
            Fixture {
                system_root,
                services,
                qword_data,
                current_control_set,
            },
        )
    }

    fn session(memory: &[u8]) -> Session {
        let session = session_over_memory(BASE, memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, layouts(), &[]);
        session
    }

    fn registry(session: &Session) -> (HiveList, Registry<'_>) {
        let target = &session.target;
        let dtb = target.current_dtb();
        let types = Types::new(
            &target.symbols,
            Some(1),
            &target.phys,
            target.arch(),
            target.kernel_dtb(),
            dtb,
        );
        let memory = target.address_space(dtb);
        let list = read_hive_list(types, &memory, VirtAddr(HEAD), Some(VirtAddr(MASTER))).unwrap();
        let registry = Registry::new(types, memory, &list).unwrap();
        (list, registry)
    }

    fn subkey_names(key: &RegKey) -> Vec<&str> {
        key.subkeys
            .iter()
            .map(|subkey| subkey.as_ref().unwrap().name.as_str())
            .collect()
    }

    #[test]
    fn the_hive_list_names_each_hive_and_its_mount_point() {
        let (memory, fixture) = registry_memory();
        let session = session(&memory);
        let (list, _) = registry(&session);
        let hives: Vec<&Hive> = list
            .hives
            .iter()
            .map(|hive| hive.as_ref().unwrap())
            .collect();
        assert_eq!(list.stopped, None);
        let [master, system] = hives.as_slice() else {
            panic!("two hives: {hives:?}");
        };
        assert!(master.master);
        assert_eq!(master.mount.as_deref(), Some("\\REGISTRY"));
        assert_eq!(system.address, VirtAddr(SYSTEM));
        assert_eq!(system.mount.as_deref(), Some(MOUNT_PATH));
        assert_eq!(
            system.root_cell,
            DiagnosticValue::Available(fixture.system_root)
        );
        assert_eq!(system.volatile.length, 0x2000);
    }

    #[test]
    fn the_cell_map_translates_stable_and_volatile_cells() {
        let (memory, fixture) = registry_memory();
        let session = session(&memory);
        let (_, registry) = registry(&session);
        let system = registry.hive(VirtAddr(SYSTEM)).unwrap();

        let (address, map) = registry.locate(system, fixture.system_root).unwrap();
        assert_eq!(
            address,
            VirtAddr(SYSTEM_BINS[0] + u64::from(fixture.system_root))
        );
        assert_eq!(map.unwrap().table, 0);

        // The fifth block of the second bin: its entry maps it 0x4000 into
        // the bin.
        assert_eq!(fixture.qword_data, 0x5000);
        let (address, map) = registry.locate(system, fixture.qword_data).unwrap();
        let map = map.unwrap();
        assert_eq!((map.directory, map.table, map.offset), (0, 5, 0));
        assert_eq!(map.entry, VirtAddr(SYSTEM_TABLES[0] + 5 * 0x18));
        assert_eq!(map.block, VirtAddr(SYSTEM_BINS[1] + 0x4000));
        assert_eq!(address, VirtAddr(SYSTEM_BINS[1] + 0x4000));

        let volatile = fixture.current_control_set;
        let (address, _) = registry.locate(system, volatile).unwrap();
        assert_eq!(
            address,
            VirtAddr(VOLATILE_BIN + u64::from(volatile & !HCELL_VOLATILE))
        );
        let node = registry.node(system, volatile).unwrap();
        assert_eq!(node.name, "CurrentControlSet");

        let unmapped = registry
            .locate(system, HCELL_VOLATILE | 0x1010)
            .unwrap_err();
        assert!(unmapped.contains("not mapped"), "{unmapped}");
        let past = registry.locate(system, 0x7000).unwrap_err();
        assert!(past.contains("past the end"), "{past}");
        let absent = registry.cell(system, 0x6020).unwrap_err();
        assert!(absent.contains("not in memory"), "{absent}");
    }

    #[test]
    fn every_kind_of_subkey_index_lists_its_keys() {
        let (memory, _) = registry_memory();
        let session = session(&memory);
        let (_, registry) = registry(&session);

        // `lf` in the master hive's root.
        let root = registry.query("\\REGISTRY").unwrap();
        assert_eq!(subkey_names(&root), ["MACHINE"]);
        // `li`, whose one entry is the link node to SYSTEM.
        let machine = registry.query("HKLM").unwrap();
        assert_eq!(subkey_names(&machine), ["SYSTEM"]);
        assert_ne!(
            machine.subkeys[0].as_ref().unwrap().flags & KEY_HIVE_EXIT,
            0
        );
        // `ri` of an `lh` and an `li` leaf, then the volatile `lf`.
        let system = registry.query("HKLM\\SYSTEM").unwrap();
        assert_eq!(system.path, MOUNT_PATH);
        assert_eq!(system.hive, VirtAddr(SYSTEM));
        assert_eq!(
            subkey_names(&system),
            ["ControlSet001", "Select", "Setup", "CurrentControlSet"]
        );
        assert_eq!(system.subkey_count, 4);
        assert!(system.problems.is_empty(), "{:?}", system.problems);
        let volatile = system.subkeys[3].as_ref().unwrap();
        assert_ne!(volatile.cell & HCELL_VOLATILE, 0);
    }

    #[test]
    fn values_decode_by_type_and_big_data_joins_its_segments() {
        let (memory, _) = registry_memory();
        let session = session(&memory);
        let (_, registry) = registry(&session);
        let key = registry
            .query("HKLM\\SYSTEM\\ControlSet001\\Services")
            .unwrap();
        let values: Vec<&RegValue> = key
            .values
            .iter()
            .map(|value| value.as_ref().unwrap())
            .collect();
        let decoded = |name: &str| {
            let value = values
                .iter()
                .find(|value| value.name == name)
                .unwrap_or_else(|| panic!("no value {name}"));
            match value.decoded() {
                DiagnosticValue::Available(data) => (value.storage, data),
                DiagnosticValue::Unavailable(error) => panic!("{name}: {error}"),
            }
        };
        assert_eq!(decoded("Start"), (DataStorage::Inline, RegData::Number(2)));
        assert_eq!(
            decoded("ImagePath"),
            (
                DataStorage::Cell,
                RegData::Text("%SystemRoot%\\x.sys".into())
            )
        );
        // The list ends at its empty string.
        assert_eq!(
            decoded("DependOnService").1,
            RegData::Strings(vec!["a".into(), "bc".into()])
        );
        assert_eq!(decoded("Blob"), (DataStorage::Big, RegData::Bytes(blob())));
        assert_eq!(decoded("Q").1, RegData::Number(0x0123_4567_89ab_cdef));
        assert_eq!(decoded("").1, RegData::Text("dflt".into()));
        assert_eq!(
            decoded("BE"),
            (DataStorage::Inline, RegData::Number(0x7856_3412))
        );

        // A subkey in a bin the dump does not hold does not read; the rest
        // of the key does.
        let [Err((_, error))] = key.subkeys.as_slice() else {
            panic!("one unreadable subkey: {:?}", key.subkeys);
        };
        assert!(error.contains("not in memory"), "{error}");
        assert!(key.problems.is_empty(), "{:?}", key.problems);
    }

    #[test]
    fn a_path_resolves_across_the_hive_link_and_the_symbolic_link() {
        let (memory, fixture) = registry_memory();
        let session = session(&memory);
        let (_, registry) = registry(&session);
        let opened = registry
            .open("hklm\\system\\currentcontrolset\\SERVICES\\")
            .unwrap();
        assert_eq!(opened.hive.address, VirtAddr(SYSTEM));
        assert_eq!(opened.cell, fixture.services);
        assert_eq!(
            opened.path,
            "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services"
        );
        assert_eq!(
            opened.links,
            [RegLink {
                from: "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet".into(),
                to: LINK_TARGET.into(),
            }]
        );

        // The link itself opens its target.
        let link = registry
            .open("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet")
            .unwrap();
        assert_eq!(link.node.name, "ControlSet001");

        let missing = registry.open("HKLM\\SYSTEM\\Nope").err().unwrap();
        assert!(
            missing
                .to_string()
                .contains("\\REGISTRY\\MACHINE\\SYSTEM has no subkey Nope"),
            "{missing}"
        );

        // A key given by its node finds its path from its parents.
        let node = registry.node(opened.hive, fixture.services).unwrap();
        let key = registry.key_at(VirtAddr(SYSTEM), node.address).unwrap();
        assert_eq!(key.path, opened.path);
    }

    #[test]
    fn path_spellings_resolve_to_registry_components() {
        let components = |path| registry_path_components(path).unwrap();
        assert_eq!(components("HKLM\\SOFTWARE"), ["MACHINE", "SOFTWARE"]);
        assert_eq!(
            components("\\REGISTRY\\USER\\.DEFAULT"),
            ["USER", ".DEFAULT"]
        );
        assert_eq!(
            components("HKEY_CLASSES_ROOT\\.txt"),
            ["MACHINE", "SOFTWARE", "Classes", ".txt"]
        );
        assert!(components("\\Registry").is_empty());
        assert!(registry_path_components("HKCU\\Software").is_err());
        assert!(registry_path_components("SOFTWARE\\Microsoft").is_err());
    }

    #[test]
    fn lh_hashes_match_the_kernels() {
        // From a Windows 11 SYSTEM hive's Services index.
        assert_eq!(name_hash(".NET CLR Data"), Some(0x3188_2764));
        assert_eq!(name_hash(".NET CLR Networking"), Some(0x5404_221a));
        assert_eq!(name_hash("ümlaut"), None);
    }
}
