//! A mapped PE image's headers decoded for `!dh`: the file and optional
//! headers, data directories, section table, debug directory (with its
//! CodeView record), and import descriptors; the export directory is read by
//! [`read_pe_exports`](super::read_pe_exports). Only what the headers point
//! at is read, through a [`PeImage`], so a paged-out or discarded directory is
//! reported on its own instead of failing the dump.

use super::{PeImage, read_image_bytes, read_image_c_string};
use crate::bytes::{get_u32, get_u64, read_u16, read_u32};
use crate::error::{Error, Result};
use crate::symbols::SymbolStore;
use pelite::image::{
    GUID, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use pelite::{PeView, Wrap};
use std::borrow::Cow;

/// `IMAGE_FILE_HEADER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// `IMAGE_OPTIONAL_HEADER32`/`64`, widened to one shape. `base_of_data`
/// exists only in the 32-bit header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    pub magic: u16,
    pub linker_version: (u8, u8),
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub operating_system_version: (u16, u16),
    pub image_version: (u16, u16),
    pub subsystem_version: (u16, u16),
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// One `IMAGE_DATA_DIRECTORY` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    pub index: usize,
    pub name: &'static str,
    /// An RVA, except for the security directory, whose value is a file
    /// offset (the certificate table is not mapped).
    pub rva: u32,
    pub size: u32,
}

/// `IMAGE_SECTION_HEADER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// Everything in the header page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHeaders {
    pub file: FileHeader,
    pub optional: OptionalHeader,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<SectionHeader>,
}

impl ImageHeaders {
    pub fn is_pe32_plus(&self) -> bool {
        self.optional.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    pub fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.directories.get(index)
    }
}

/// The CodeView record an `IMAGE_DEBUG_TYPE_CODEVIEW` entry points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeView {
    /// PDB 7.0: a GUID, an age, and the PDB path.
    Rsds { guid: GUID, age: u32, path: String },
    /// PDB 2.0: a timestamp signature, an age, and the PDB path.
    Nb10 {
        signature: u32,
        age: u32,
        path: String,
    },
}

/// One `IMAGE_DEBUG_DIRECTORY` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugDirectoryEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub version: (u16, u16),
    pub kind: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// A debug directory entry as `!dh` shows it, with its CodeView record
/// decoded when it is one: `Err` says why the record could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugRecord {
    pub entry: DebugDirectoryEntry,
    pub codeview: Option<std::result::Result<CodeView, String>>,
}

/// How an import names what it imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportName {
    Ordinal(u16),
    Name {
        hint: u16,
        name: String,
    },
    /// The descriptor has no import name table, and the IAT the loader bound
    /// holds addresses rather than names: only the bound address is known.
    Unnamed,
    /// The hint/name entry does not read; says why.
    Unreadable(String),
}

/// One import-name-table entry and the import address table slot beside
/// it: what the loader bound there, or `None` when that slot is unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub name: ImportName,
    pub bound: Option<u64>,
}

/// One `IMAGE_IMPORT_DESCRIPTOR` and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    /// The module imported from, or why its name does not read.
    pub name: std::result::Result<String, String>,
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub first_thunk: u32,
    pub entries: Vec<ImportEntry>,
    /// Why `entries` stops short of the table's end: a thunk that does not
    /// read, or no terminator within the bound. `None` when the table was
    /// read to its terminator.
    pub incomplete: Option<String>,
}

const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// Real images carry a handful of debug entries; the size is guest data.
const MAX_DEBUG_DIRECTORY_BYTES: usize = 0x1000;
/// A CodeView record is a GUID, an age, and a PDB path.
const MAX_CODEVIEW_BYTES: usize = 0x1000;
/// Bounds on guest-controlled import tables: ntoskrnl imports from about a
/// dozen modules, a few hundred functions each.
const MAX_IMPORT_DESCRIPTORS: usize = 4096;
const MAX_IMPORTS_PER_DESCRIPTOR: usize = 65_536;

const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "Base Relocation",
    "Debug",
    "Description",
    "Special",
    "Thread Storage",
    "Load Configuration",
    "Bound Import",
    "Import Address Table",
    "Delay Import",
    "COR20 Header",
    "Reserved",
];

/// Decode the file header, optional header, data directories, and section
/// table from an image's header bytes.
pub fn decode_headers(headers: &[u8]) -> Result<ImageHeaders> {
    let view = PeView::from_bytes(headers)?;
    let header = view.file_header();
    let file = FileHeader {
        machine: header.Machine,
        number_of_sections: header.NumberOfSections,
        time_date_stamp: header.TimeDateStamp,
        pointer_to_symbol_table: header.PointerToSymbolTable,
        number_of_symbols: header.NumberOfSymbols,
        size_of_optional_header: header.SizeOfOptionalHeader,
        characteristics: header.Characteristics,
    };
    let optional = match view.optional_header() {
        Wrap::T32(h) => OptionalHeader {
            magic: h.Magic,
            linker_version: (h.LinkerVersion.Major, h.LinkerVersion.Minor),
            size_of_code: h.SizeOfCode,
            size_of_initialized_data: h.SizeOfInitializedData,
            size_of_uninitialized_data: h.SizeOfUninitializedData,
            address_of_entry_point: h.AddressOfEntryPoint,
            base_of_code: h.BaseOfCode,
            base_of_data: Some(h.BaseOfData),
            image_base: u64::from(h.ImageBase),
            section_alignment: h.SectionAlignment,
            file_alignment: h.FileAlignment,
            operating_system_version: (
                h.OperatingSystemVersion.Major,
                h.OperatingSystemVersion.Minor,
            ),
            image_version: (h.ImageVersion.Major, h.ImageVersion.Minor),
            subsystem_version: (h.SubsystemVersion.Major, h.SubsystemVersion.Minor),
            win32_version_value: h.Win32VersionValue,
            size_of_image: h.SizeOfImage,
            size_of_headers: h.SizeOfHeaders,
            checksum: h.CheckSum,
            subsystem: h.Subsystem,
            dll_characteristics: h.DllCharacteristics,
            size_of_stack_reserve: u64::from(h.SizeOfStackReserve),
            size_of_stack_commit: u64::from(h.SizeOfStackCommit),
            size_of_heap_reserve: u64::from(h.SizeOfHeapReserve),
            size_of_heap_commit: u64::from(h.SizeOfHeapCommit),
            loader_flags: h.LoaderFlags,
            number_of_rva_and_sizes: h.NumberOfRvaAndSizes,
        },
        Wrap::T64(h) => OptionalHeader {
            magic: h.Magic,
            linker_version: (h.LinkerVersion.Major, h.LinkerVersion.Minor),
            size_of_code: h.SizeOfCode,
            size_of_initialized_data: h.SizeOfInitializedData,
            size_of_uninitialized_data: h.SizeOfUninitializedData,
            address_of_entry_point: h.AddressOfEntryPoint,
            base_of_code: h.BaseOfCode,
            base_of_data: None,
            image_base: h.ImageBase,
            section_alignment: h.SectionAlignment,
            file_alignment: h.FileAlignment,
            operating_system_version: (
                h.OperatingSystemVersion.Major,
                h.OperatingSystemVersion.Minor,
            ),
            image_version: (h.ImageVersion.Major, h.ImageVersion.Minor),
            subsystem_version: (h.SubsystemVersion.Major, h.SubsystemVersion.Minor),
            win32_version_value: h.Win32VersionValue,
            size_of_image: h.SizeOfImage,
            size_of_headers: h.SizeOfHeaders,
            checksum: h.CheckSum,
            subsystem: h.Subsystem,
            dll_characteristics: h.DllCharacteristics,
            size_of_stack_reserve: h.SizeOfStackReserve,
            size_of_stack_commit: h.SizeOfStackCommit,
            size_of_heap_reserve: h.SizeOfHeapReserve,
            size_of_heap_commit: h.SizeOfHeapCommit,
            loader_flags: h.LoaderFlags,
            number_of_rva_and_sizes: h.NumberOfRvaAndSizes,
        },
    };
    let directories = view
        .data_directory()
        .iter()
        .enumerate()
        .map(|(index, entry)| DataDirectory {
            index,
            name: DIRECTORY_NAMES.get(index).copied().unwrap_or("Unknown"),
            rva: entry.VirtualAddress,
            size: entry.Size,
        })
        .collect();
    let sections = view
        .section_headers()
        .iter()
        .map(|section| SectionHeader {
            name: String::from_utf8_lossy(section.name_bytes()).into_owned(),
            virtual_size: section.VirtualSize,
            virtual_address: section.VirtualAddress,
            size_of_raw_data: section.SizeOfRawData,
            pointer_to_raw_data: section.PointerToRawData,
            pointer_to_relocations: section.PointerToRelocations,
            pointer_to_linenumbers: section.PointerToLinenumbers,
            number_of_relocations: section.NumberOfRelocations,
            number_of_linenumbers: section.NumberOfLinenumbers,
            characteristics: section.Characteristics,
        })
        .collect();
    Ok(ImageHeaders {
        file,
        optional,
        directories,
        sections,
    })
}

/// The entries of the debug directory at `rva` (`size` bytes), read through
/// `read`, which reads `len` bytes at an RVA of the image and names what it
/// reads for its errors. An image without a debug directory has none.
pub fn read_debug_directory<'a>(
    rva: u32,
    size: u32,
    read: impl Fn(u32, usize, &str) -> Result<Cow<'a, [u8]>>,
) -> Result<Vec<DebugDirectoryEntry>> {
    if rva == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let size = size as usize;
    if !size.is_multiple_of(DEBUG_DIRECTORY_ENTRY_SIZE) || size > MAX_DEBUG_DIRECTORY_BYTES {
        return Err(Error::DebugInfo(format!(
            "debug directory size {size:#x} is not a multiple of {DEBUG_DIRECTORY_ENTRY_SIZE} \
             bytes up to {MAX_DEBUG_DIRECTORY_BYTES:#x}"
        )));
    }
    let bytes = read(rva, size, "debug directory")?;
    Ok(bytes
        .as_chunks::<DEBUG_DIRECTORY_ENTRY_SIZE>()
        .0
        .iter()
        .map(|entry| DebugDirectoryEntry {
            characteristics: read_u32(entry, 0),
            time_date_stamp: read_u32(entry, 4),
            version: (read_u16(entry, 8), read_u16(entry, 10)),
            kind: read_u32(entry, 12),
            size_of_data: read_u32(entry, 16),
            address_of_raw_data: read_u32(entry, 20),
            pointer_to_raw_data: read_u32(entry, 24),
        })
        .collect())
}

impl DebugDirectoryEntry {
    /// The CodeView record this entry points at, read through `read` (see
    /// [`read_debug_directory`]); `None` when the entry is not a CodeView one.
    pub fn read_codeview<'a>(
        &self,
        read: impl Fn(u32, usize, &str) -> Result<Cow<'a, [u8]>>,
    ) -> Option<Result<CodeView>> {
        (self.kind == IMAGE_DEBUG_TYPE_CODEVIEW).then(|| {
            if self.address_of_raw_data == 0 {
                return Err(Error::DebugInfo(
                    "the CodeView record is not mapped (AddressOfRawData is 0)".into(),
                ));
            }
            let size = self.size_of_data as usize;
            if size > MAX_CODEVIEW_BYTES {
                return Err(Error::DebugInfo(format!(
                    "CodeView record size {size:#x} exceeds {MAX_CODEVIEW_BYTES:#x}"
                )));
            }
            decode_codeview(&read(self.address_of_raw_data, size, "CodeView record")?)
        })
    }
}

/// The debug directory of `image`, each CodeView record decoded.
pub fn debug_directory(image: &PeImage, headers: &ImageHeaders) -> Result<Vec<DebugRecord>> {
    let Some(directory) = headers.directory(IMAGE_DIRECTORY_ENTRY_DEBUG) else {
        return Ok(Vec::new());
    };
    let read = |rva: u32, len: usize, what: &str| read_image_bytes(image, rva, len, what);
    Ok(read_debug_directory(directory.rva, directory.size, read)?
        .into_iter()
        .map(|entry| DebugRecord {
            codeview: entry
                .read_codeview(read)
                .map(|record| record.map_err(|error| error.to_string())),
            entry,
        })
        .collect())
}

/// Decode an RSDS (PDB 7.0) or NB10 (PDB 2.0) CodeView record.
pub fn decode_codeview(bytes: &[u8]) -> Result<CodeView> {
    let path =
        |start: usize| SymbolStore::read_c_string_lossy(bytes.get(start..).unwrap_or_default());
    match bytes.get(..4) {
        Some(b"RSDS") if bytes.len() >= 24 => Ok(CodeView::Rsds {
            guid: GUID {
                Data1: read_u32(bytes, 4),
                Data2: read_u16(bytes, 8),
                Data3: read_u16(bytes, 10),
                Data4: bytes[12..20].try_into().unwrap_or_default(),
            },
            age: read_u32(bytes, 20),
            path: path(24),
        }),
        Some(b"NB10") if bytes.len() >= 16 => Ok(CodeView::Nb10 {
            signature: read_u32(bytes, 8),
            age: read_u32(bytes, 12),
            path: path(16),
        }),
        Some(magic) => Err(Error::DebugInfo(format!(
            "unrecognized or truncated CodeView record (magic {:?}, {} bytes)",
            String::from_utf8_lossy(magic),
            bytes.len()
        ))),
        None => Err(Error::DebugInfo("CodeView record is truncated".into())),
    }
}

/// The import descriptors and their entries. Only a descriptor that does not
/// read fails the directory; a module name, an import name, or a thunk that
/// does not read is reported in its descriptor beside the rest.
pub fn imports(image: &PeImage, headers: &ImageHeaders) -> Result<Vec<ImportDescriptor>> {
    let Some(directory) = headers
        .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .filter(|directory| directory.rva != 0 && directory.size != 0)
    else {
        return Ok(Vec::new());
    };
    let wide = headers.is_pe32_plus();
    let mut descriptors = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let rva = directory
            .rva
            .checked_add((index * IMPORT_DESCRIPTOR_SIZE) as u32)
            .ok_or_else(|| Error::DebugInfo("import directory overflows the image".into()))?;
        let bytes = read_image_bytes(image, rva, IMPORT_DESCRIPTOR_SIZE, "import descriptor")?;
        let u32_at = |offset| read_u32(&bytes, offset);
        let (original_first_thunk, name, first_thunk) = (u32_at(0), u32_at(12), u32_at(16));
        if first_thunk == 0 && original_first_thunk == 0 && name == 0 {
            return Ok(descriptors);
        }
        let (entries, incomplete) = import_entries(image, original_first_thunk, first_thunk, wide);
        descriptors.push(ImportDescriptor {
            name: read_image_c_string(image, name, "import module name")
                .map_err(|error| error.to_string()),
            original_first_thunk,
            time_date_stamp: u32_at(4),
            forwarder_chain: u32_at(8),
            first_thunk,
            entries,
            incomplete,
        });
    }
    Err(Error::DebugInfo(format!(
        "import directory has no terminating descriptor within {MAX_IMPORT_DESCRIPTORS} entries"
    )))
}

/// A descriptor's entries, and why they stop short of the table's end if they
/// do. Names come from the import name table (`OriginalFirstThunk`), which the
/// loader leaves alone. Without one only the IAT is left, and in a loaded
/// image it holds the addresses the loader bound, not names: its entries are
/// [`ImportName::Unnamed`].
fn import_entries(
    image: &PeImage,
    name_table: u32,
    address_table: u32,
    wide: bool,
) -> (Vec<ImportEntry>, Option<String>) {
    let width = if wide { 8 } else { 4 };
    let thunk = |table: u32, index: usize| -> Option<u64> {
        let rva = table.checked_add(u32::try_from(index * width).ok()?)?;
        let bytes = image.read(rva as usize, width)?;
        if wide {
            get_u64(&bytes, 0)
        } else {
            get_u32(&bytes, 0).map(u64::from)
        }
    };
    let (table, what) = if name_table != 0 {
        (name_table, "import name table")
    } else {
        (address_table, "import address table")
    };
    let mut entries = Vec::new();
    if table == 0 {
        return (entries, None);
    }
    for index in 0..MAX_IMPORTS_PER_DESCRIPTOR {
        let Some(value) = thunk(table, index) else {
            return (
                entries,
                Some(format!(
                    "{what} entry {index} (table at RVA {table:#x}) is not resident"
                )),
            );
        };
        if value == 0 {
            return (entries, None);
        }
        entries.push(if name_table == 0 {
            ImportEntry {
                name: ImportName::Unnamed,
                bound: Some(value),
            }
        } else {
            ImportEntry {
                name: import_name(image, value, wide),
                bound: (address_table != 0)
                    .then(|| thunk(address_table, index))
                    .flatten(),
            }
        });
    }
    (
        entries,
        Some(format!(
            "{what} at RVA {table:#x} has no terminator within {MAX_IMPORTS_PER_DESCRIPTOR} entries"
        )),
    )
}

/// What an import name table entry names: an ordinal when its top bit is
/// set, otherwise the RVA of a hint and a name.
fn import_name(image: &PeImage, thunk: u64, wide: bool) -> ImportName {
    let ordinal_flag = if wide { 1u64 << 63 } else { 1u64 << 31 };
    if thunk & ordinal_flag != 0 {
        return ImportName::Ordinal(thunk as u16);
    }
    let rva = (thunk & 0x7fff_ffff) as u32;
    let hint_and_name = || -> Result<ImportName> {
        let hint = read_image_bytes(image, rva, 2, "import hint")?;
        Ok(ImportName::Name {
            hint: read_u16(&hint, 0),
            name: read_image_c_string(image, rva + 2, "import name")?,
        })
    };
    hint_and_name().unwrap_or_else(|error| ImportName::Unreadable(error.to_string()))
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "X86",
        0x8664 => "X64",
        0xaa64 => "ARM64",
        0xa641 => "ARM64EC",
        0xa64e => "ARM64X",
        0x01c4 => "ARMNT",
        0x0200 => "IA64",
        0 => "Unknown",
        _ => "unrecognized",
    }
}

pub fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        8 => "Native Win9x driver",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "unrecognized",
    }
}

pub fn debug_type_name(kind: u32) -> &'static str {
    match kind {
        0 => "unknown",
        1 => "coff",
        2 => "cv",
        3 => "fpo",
        4 => "misc",
        5 => "exception",
        6 => "fixup",
        7 => "omap_to_src",
        8 => "omap_from_src",
        9 => "borland",
        10 => "bbt",
        11 => "clsid",
        12 => "vc_feature",
        13 => "pogo",
        14 => "iltcg",
        15 => "mpx",
        16 => "repro",
        17 => "embedded_pdb",
        18 => "spgo",
        19 => "pdb_checksum",
        20 => "ex_dllcharacteristics",
        _ => "unrecognized",
    }
}

const FILE_CHARACTERISTICS: [(u32, &str); 15] = [
    (0x0001, "Relocations stripped"),
    (0x0002, "Executable"),
    (0x0004, "Line numbers stripped"),
    (0x0008, "Symbols stripped"),
    (0x0010, "Aggressively trim working set"),
    (0x0020, "App can handle >2gb addresses"),
    (0x0080, "Bytes reversed (low)"),
    (0x0100, "32 bit word machine"),
    (0x0200, "Debug information stripped"),
    (0x0400, "Removable run from swap"),
    (0x0800, "Net run from swap"),
    (0x1000, "System"),
    (0x2000, "DLL"),
    (0x4000, "Uniprocessor only"),
    (0x8000, "Bytes reversed (high)"),
];

const DLL_CHARACTERISTICS: [(u32, &str); 11] = [
    (0x0020, "High entropy VA supported"),
    (0x0040, "Dynamic base"),
    (0x0080, "Force integrity"),
    (0x0100, "NX compatible"),
    (0x0200, "No isolation"),
    (0x0400, "No SEH"),
    (0x0800, "Do not bind"),
    (0x1000, "AppContainer"),
    (0x2000, "WDM driver"),
    (0x4000, "Guard"),
    (0x8000, "Terminal server aware"),
];

const SECTION_CHARACTERISTICS: [(u32, &str); 13] = [
    (0x0000_0008, "No pad"),
    (0x0000_0020, "Code"),
    (0x0000_0040, "Initialized Data"),
    (0x0000_0080, "Uninitialized Data"),
    (0x0000_0200, "Info"),
    (0x0000_0800, "Remove"),
    (0x0000_1000, "Comdat"),
    (0x0000_8000, "GP relative"),
    (0x0100_0000, "Extended relocations"),
    (0x0200_0000, "Discardable"),
    (0x0400_0000, "Not Cached"),
    (0x0800_0000, "Not Paged"),
    (0x1000_0000, "Shared"),
];

/// The named flags set in `value`, then any unnamed bits as one hex value.
fn flag_names(value: u32, table: &[(u32, &str)]) -> Vec<String> {
    let mut names = Vec::new();
    let mut known = 0;
    for &(bit, name) in table {
        known |= bit;
        if value & bit != 0 {
            names.push(name.to_string());
        }
    }
    let rest = value & !known;
    if rest != 0 {
        names.push(format!("unknown bits {rest:#x}"));
    }
    names
}

pub fn file_characteristics(value: u16) -> Vec<String> {
    flag_names(value.into(), &FILE_CHARACTERISTICS)
}

pub fn dll_characteristics(value: u16) -> Vec<String> {
    flag_names(value.into(), &DLL_CHARACTERISTICS)
}

/// A section's flags as WinDbg lists them: content and memory flags, the
/// alignment, then its access (`Execute Read Write`).
pub fn section_characteristics(value: u32) -> Vec<String> {
    const ALIGN_MASK: u32 = 0x00f0_0000;
    const ACCESS: [(u32, &str); 3] = [
        (0x2000_0000, "Execute"),
        (0x4000_0000, "Read"),
        (0x8000_0000, "Write"),
    ];
    let known = ALIGN_MASK | ACCESS.iter().fold(0, |mask, (bit, _)| mask | bit);
    let mut names = flag_names(value & !known, &SECTION_CHARACTERISTICS);
    let align = (value & ALIGN_MASK) >> 20;
    names.push(match align {
        0 => "(no align specified)".to_string(),
        1..=14 => format!("({} byte align)", 1u32 << (align - 1)),
        _ => format!("(invalid alignment {align:#x})"),
    });
    let access: Vec<&str> = ACCESS
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    names.push(match access.as_slice() {
        [] => "No access".to_string(),
        [only] if *only == "Read" => "Read Only".to_string(),
        many => many.join(" "),
    });
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VirtAddr;

    #[test]
    fn section_flags_decode_alignment_and_access_like_windbg() {
        // ntoskrnl's .text and INIT, read live on build 26200.
        assert_eq!(
            section_characteristics(0x6800_0020),
            ["Code", "Not Paged", "(no align specified)", "Execute Read"]
        );
        assert_eq!(
            section_characteristics(0x6200_0020),
            [
                "Code",
                "Discardable",
                "(no align specified)",
                "Execute Read"
            ]
        );
        assert_eq!(
            section_characteristics(0xc000_0040),
            ["Initialized Data", "(no align specified)", "Read Write"]
        );
        assert_eq!(
            section_characteristics(0x4030_0040),
            ["Initialized Data", "(4 byte align)", "Read Only"]
        );
        assert_eq!(
            section_characteristics(0x0000_4000),
            ["unknown bits 0x4000", "(no align specified)", "No access"]
        );
    }

    #[test]
    fn codeview_rsds_guid_is_decoded_from_its_mixed_endian_fields() {
        let mut record = b"RSDS".to_vec();
        record.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ]);
        record.extend_from_slice(&3u32.to_le_bytes());
        record.extend_from_slice(b"ntkrnlmp.pdb\0junk");
        assert_eq!(
            decode_codeview(&record).unwrap(),
            CodeView::Rsds {
                guid: GUID {
                    Data1: 0x1234_5678,
                    Data2: 0x9abc,
                    Data3: 0xdef0,
                    Data4: [1, 2, 3, 4, 5, 6, 7, 8],
                },
                age: 3,
                path: "ntkrnlmp.pdb".into(),
            }
        );
        assert!(decode_codeview(b"RSDS\0\0").is_err());
    }

    /// Bytes past this RVA of [`image_with_imports`] do not read.
    const SECOND_NAME: usize = 0x1800;

    /// A PE32 or PE32+ image importing two names and one ordinal from
    /// `hal.dll`, whose IAT holds bound addresses as a loaded image's does.
    /// The second name sits in the last block, at [`SECOND_NAME`].
    fn image_with_imports(wide: bool) -> Vec<u8> {
        let mut image = vec![0u8; 0x2000];
        let mut put = |at: usize, bytes: &[u8]| image[at..at + bytes.len()].copy_from_slice(bytes);
        let pe = 0x80;
        put(0, b"MZ");
        put(0x3c, &(pe as u32).to_le_bytes());
        put(pe, b"PE\0\0");
        put(
            pe + 4,
            &(if wide { 0x8664u16 } else { 0x14c }).to_le_bytes(),
        );
        put(pe + 6, &1u16.to_le_bytes());
        let optional_size: u16 = if wide { 240 } else { 224 };
        put(pe + 20, &optional_size.to_le_bytes());
        let opt = pe + 24;
        put(opt, &(if wide { 0x20bu16 } else { 0x10b }).to_le_bytes());
        put(opt + 32, &0x1000u32.to_le_bytes());
        put(opt + 36, &0x200u32.to_le_bytes());
        put(opt + 56, &0x2000u32.to_le_bytes());
        put(opt + 60, &0x1000u32.to_le_bytes());
        let (count, directories) = if wide { (108, 112) } else { (92, 96) };
        put(opt + count, &16u32.to_le_bytes());
        let import = opt + directories + 8;
        put(import, &0x1000u32.to_le_bytes());
        put(import + 4, &40u32.to_le_bytes());
        let section = opt + usize::from(optional_size);
        put(section, b".rdata\0\0");
        put(section + 8, &0x1000u32.to_le_bytes());
        put(section + 12, &0x1000u32.to_le_bytes());
        // Descriptor, then a null one.
        put(0x1000, &0x1100u32.to_le_bytes());
        put(0x1000 + 12, &0x1300u32.to_le_bytes());
        put(0x1000 + 16, &0x1200u32.to_le_bytes());
        put(0x1300, b"hal.dll\0");
        put(0x1400, &7u16.to_le_bytes());
        put(0x1402, b"HalGetBusData\0");
        put(SECOND_NAME, &9u16.to_le_bytes());
        put(SECOND_NAME + 2, b"HalSetBusData\0");
        let width = if wide { 8 } else { 4 };
        let ordinal = if wide {
            (1u64 << 63) | 12
        } else {
            (1u64 << 31) | 12
        };
        for (index, name) in [0x1400u64, SECOND_NAME as u64, ordinal]
            .into_iter()
            .enumerate()
        {
            put(0x1100 + index * width, &name.to_le_bytes()[..width]);
            put(
                0x1200 + index * width,
                &bound(wide, index).to_le_bytes()[..width],
            );
        }
        image
    }

    /// What the loader bound in IAT slot `index` of [`image_with_imports`]:
    /// a kernel address, whose top bit is the name table's ordinal flag.
    fn bound(wide: bool, index: usize) -> u64 {
        let base = if wide {
            0xffff_f801_0000_1000
        } else {
            0x8001_1000
        };
        base + 0x100 * index as u64
    }

    /// `bytes` as a lazily read image whose bytes from `readable` on do not
    /// read, like a paged-out page.
    fn lazy_image(bytes: Vec<u8>, readable: usize) -> PeImage {
        super::super::read_pe_image(VirtAddr(0), move |address, buf| {
            let start = address.0 as usize;
            if start + buf.len() > readable {
                return Err(Error::BadVirtualAddress(address));
            }
            buf.copy_from_slice(&bytes[start..start + buf.len()]);
            Ok(())
        })
        .unwrap()
    }

    fn imports_of(image: &PeImage) -> Vec<ImportDescriptor> {
        imports(image, &decode_headers(image.headers()).unwrap()).unwrap()
    }

    #[test]
    fn imports_read_names_and_ordinals_from_the_name_table_of_either_width() {
        for wide in [true, false] {
            let descriptors = imports_of(&PeImage::complete(image_with_imports(wide)));
            assert_eq!(descriptors.len(), 1, "wide={wide}");
            assert_eq!(descriptors[0].name.as_deref(), Ok("hal.dll"));
            assert_eq!(descriptors[0].incomplete, None);
            assert_eq!(
                descriptors[0].entries,
                [
                    ImportEntry {
                        name: ImportName::Name {
                            hint: 7,
                            name: "HalGetBusData".into()
                        },
                        bound: Some(bound(wide, 0)),
                    },
                    ImportEntry {
                        name: ImportName::Name {
                            hint: 9,
                            name: "HalSetBusData".into()
                        },
                        bound: Some(bound(wide, 1)),
                    },
                    ImportEntry {
                        name: ImportName::Ordinal(12),
                        bound: Some(bound(wide, 2)),
                    },
                ],
                "wide={wide}"
            );
        }
    }

    /// A name on a page that does not read costs that entry its name, not
    /// the descriptor or the directory.
    #[test]
    fn an_unreadable_import_name_is_reported_on_its_entry_alone() {
        let descriptors = imports_of(&lazy_image(image_with_imports(true), SECOND_NAME));
        let entries = &descriptors[0].entries;
        assert_eq!(descriptors[0].name.as_deref(), Ok("hal.dll"));
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0].name, ImportName::Name { hint: 7, .. }));
        assert!(matches!(entries[1].name, ImportName::Unreadable(_)));
        assert_eq!(entries[1].bound, Some(bound(true, 1)));
        assert_eq!(entries[2].name, ImportName::Ordinal(12));
    }

    /// Without an import name table the IAT holds bound addresses, which are
    /// not decoded as names or ordinals even with the ordinal bit set.
    #[test]
    fn a_bound_iat_without_a_name_table_yields_addresses_only() {
        for wide in [true, false] {
            let mut bytes = image_with_imports(wide);
            bytes[0x1000..0x1004].fill(0);
            let descriptors = imports_of(&PeImage::complete(bytes));
            assert_eq!(descriptors[0].incomplete, None, "wide={wide}");
            assert_eq!(
                descriptors[0].entries,
                (0..3)
                    .map(|index| ImportEntry {
                        name: ImportName::Unnamed,
                        bound: Some(bound(wide, index)),
                    })
                    .collect::<Vec<_>>(),
                "wide={wide}"
            );
        }
    }
}
