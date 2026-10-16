//! Parses the streams of a Windows user-mode minidump (`MDMP`): the header
//! and stream directory, and the thread, module, memory, exception, system
//! and process information streams a debugger reads. Every count, size and
//! RVA comes from the file and is checked against it; a damaged record is
//! dropped with a note saying why, and only a file whose header, directory,
//! or system information cannot be read is refused.

use std::collections::{BTreeMap, HashMap};

use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::{
    CapturedStack, DynamicFunction, FunctionTable, MemoryRange, MemoryRegion, UnloadedModule,
    UserDumpInfo, UserException, UserHandle, UserModule, UserSystemInfo, UserThreadInfo,
    UserThreadTimes, UserTimeZone,
};
use crate::bytes::{utf16le_lossy, utf16le_nul_terminated};
use crate::cpu_context::{amd64, arm64};
use crate::error::{Error, Result};
use crate::pe::headers::{MAX_CODEVIEW_BYTES, decode_codeview};
use crate::types::Arch;

/// `MINIDUMP_SIGNATURE`: "MDMP" read as a little-endian `u32`.
pub const MINIDUMP_SIGNATURE: u32 = 0x504d_444d;
/// The low word of `MINIDUMP_HEADER.Version`.
const MINIDUMP_VERSION: u16 = 0xa793;

const UNUSED_STREAM: u32 = 0;
const THREAD_LIST_STREAM: u32 = 3;
const MODULE_LIST_STREAM: u32 = 4;
const MEMORY_LIST_STREAM: u32 = 5;
const EXCEPTION_STREAM: u32 = 6;
const SYSTEM_INFO_STREAM: u32 = 7;
const MEMORY64_LIST_STREAM: u32 = 9;
const HANDLE_DATA_STREAM: u32 = 12;
const FUNCTION_TABLE_STREAM: u32 = 13;
const UNLOADED_MODULE_LIST_STREAM: u32 = 14;
const MISC_INFO_STREAM: u32 = 15;
const MEMORY_INFO_LIST_STREAM: u32 = 16;
const THREAD_INFO_LIST_STREAM: u32 = 17;
const THREAD_NAME_LIST_STREAM: u32 = 24;

/// `VER_PLATFORM_WIN32_NT`, the only platform a Windows minidump names.
const PLATFORM_WIN32_NT: u32 = 2;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;

const MISC1_PROCESS_ID: u32 = 0x1;
const MISC1_PROCESS_TIMES: u32 = 0x2;
const MISC3_TIMEZONE: u32 = 0x40;
const MISC4_BUILDSTRING: u32 = 0x100;
/// `MINIDUMP_MISC_INFO_3.TimeZoneId` and the `TIME_ZONE_INFORMATION` that
/// follows it.
const MISC_INFO_TIME_ZONE_ID: usize = 56;
const MISC_INFO_TIME_ZONE: usize = 60;
const TIME_ZONE_INFORMATION_SIZE: usize = 172;
const TIME_ZONE_ID_UNKNOWN: u32 = 0;
const TIME_ZONE_ID_STANDARD: u32 = 1;
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
/// `MINIDUMP_MISC_INFO_4.BuildString`: 260 UTF-16 units after the 232 bytes
/// of `MINIDUMP_MISC_INFO_3`.
const MISC_INFO_BUILD_STRING: usize = 232;
const MISC_INFO_BUILD_STRING_UNITS: usize = 260;

/// More streams, records, or ranges than this is no dump a debugger wrote;
/// the bounds keep a corrupt count from driving the parser for minutes.
const MAX_STREAMS: u32 = 0x1000;
const MAX_THREADS: u32 = 0x10_0000;
const MAX_MODULES: u32 = 0x10_0000;
const MAX_MEMORY_RANGES: u64 = 0x100_0000;
const MAX_HANDLES: u32 = 0x100_0000;
const MAX_FUNCTION_TABLES: u32 = 0x10_0000;
/// An AMD64 `RUNTIME_FUNCTION`: begin, end, and unwind-data offsets.
const AMD64_RUNTIME_FUNCTION_SIZE: u32 = 12;
/// An ARM64 `RUNTIME_FUNCTION`: begin and unwind-data offsets; the length
/// is in the packed unwind data or the `.xdata` header.
const ARM64_RUNTIME_FUNCTION_SIZE: u32 = 8;
/// The longest `MINIDUMP_STRING` read, in bytes: a module path or thread
/// name is far shorter.
const MAX_STRING_BYTES: u32 = 0x1_0000;

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawHeader {
    signature: u32,
    version: u32,
    number_of_streams: u32,
    stream_directory_rva: u32,
    check_sum: u32,
    time_date_stamp: u32,
    flags: u64,
}

#[derive(FromBytes, Immutable, KnownLayout, Clone, Copy)]
#[repr(C, packed)]
struct Location {
    data_size: u32,
    rva: u32,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawDirectory {
    stream_type: u32,
    location: Location,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMemoryDescriptor {
    start: u64,
    memory: Location,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMemoryDescriptor64 {
    start: u64,
    data_size: u64,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawThread {
    thread_id: u32,
    suspend_count: u32,
    priority_class: u32,
    priority: u32,
    teb: u64,
    stack: RawMemoryDescriptor,
    context: Location,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawModule {
    base_of_image: u64,
    size_of_image: u32,
    check_sum: u32,
    time_date_stamp: u32,
    module_name_rva: u32,
    /// `VS_FIXEDFILEINFO`.
    version_info: [u32; 13],
    cv_record: Location,
    misc_record: Location,
    reserved0: u64,
    reserved1: u64,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawUnloadedModule {
    base_of_image: u64,
    size_of_image: u32,
    check_sum: u32,
    time_date_stamp: u32,
    module_name_rva: u32,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawException {
    thread_id: u32,
    alignment: u32,
    code: u32,
    flags: u32,
    record: u64,
    address: u64,
    number_parameters: u32,
    unused_alignment: u32,
    information: [u64; 15],
    context: Location,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawSystemInfo {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    number_of_processors: u8,
    product_type: u8,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    csd_version_rva: u32,
    suite_mask: u16,
    reserved2: u16,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMiscInfo {
    size_of_info: u32,
    flags1: u32,
    process_id: u32,
    process_create_time: u32,
    process_user_time: u32,
    process_kernel_time: u32,
}

/// The header of the list streams whose entry size is recorded rather than
/// fixed (`MINIDUMP_THREAD_INFO_LIST`, `MINIDUMP_UNLOADED_MODULE_LIST`).
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawSizedListHeader {
    size_of_header: u32,
    size_of_entry: u32,
    number_of_entries: u32,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawThreadInfo {
    thread_id: u32,
    dump_flags: u32,
    dump_error: u32,
    exit_status: u32,
    create_time: u64,
    exit_time: u64,
    kernel_time: u64,
    user_time: u64,
    start_address: u64,
    affinity: u64,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawThreadName {
    thread_id: u32,
    name_rva: u64,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawHandleDataHeader {
    size_of_header: u32,
    size_of_descriptor: u32,
    number_of_descriptors: u32,
    reserved: u32,
}

/// `MINIDUMP_HANDLE_DESCRIPTOR`; `MINIDUMP_HANDLE_DESCRIPTOR_2` appends an
/// object-information RVA, which this does not read.
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawHandleDescriptor {
    handle: u64,
    type_name_rva: u32,
    object_name_rva: u32,
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMemoryInfoListHeader {
    size_of_header: u32,
    size_of_entry: u32,
    number_of_entries: u64,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawMemoryInfo {
    base_address: u64,
    allocation_base: u64,
    allocation_protect: u32,
    alignment1: u32,
    region_size: u64,
    state: u32,
    protect: u32,
    kind: u32,
    alignment2: u32,
}

#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawFunctionTableHeader {
    size_of_header: u32,
    size_of_descriptor: u32,
    size_of_native_descriptor: u32,
    size_of_function_entry: u32,
    number_of_descriptors: u32,
    /// Padding between the header and the first descriptor.
    size_of_align_pad: u32,
}

/// `MINIDUMP_FUNCTION_TABLE_DESCRIPTOR`, which is followed by the native
/// table descriptor, `entry_count` function entries, and `size_of_align_pad`
/// bytes of padding.
#[derive(FromBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
struct RawFunctionTableDescriptor {
    minimum_address: u64,
    maximum_address: u64,
    base_address: u64,
    entry_count: u32,
    size_of_align_pad: u32,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidDump(message.into())
}

/// The `T` at `offset` of `data`, `None` when it does not fit.
fn read_at<T: FromBytes>(data: &[u8], offset: u64) -> Option<T> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(size_of::<T>())?;
    T::read_from_bytes(data.get(start..end)?).ok()
}

/// The bytes a location descriptor names, `None` when they leave the file.
fn located(data: &[u8], rva: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(rva).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    data.get(start..end)
}

/// The `MINIDUMP_STRING` at `rva`: a byte length, then that many bytes of
/// UTF-16LE.
fn read_string(data: &[u8], rva: u64) -> std::result::Result<String, String> {
    let length: u32 =
        read_at(data, rva).ok_or_else(|| format!("string at {rva:#x} is outside the file"))?;
    if length > MAX_STRING_BYTES || !length.is_multiple_of(2) {
        return Err(format!(
            "string at {rva:#x} has an invalid length {length:#x}"
        ));
    }
    let bytes = located(data, rva + 4, u64::from(length))
        .ok_or_else(|| format!("string at {rva:#x} ({length} bytes) leaves the file"))?;
    Ok(utf16le_lossy(bytes))
}

/// What a `MINIDUMP_SYSTEM_INFO.PlatformId` that is not Windows NT names,
/// with Breakpad's extensions (`MD_OS_*`).
fn platform_name(platform: u32) -> &'static str {
    match platform {
        0 => "Win32s",
        1 => "Windows 9x",
        0x8000 => "Unix",
        0x8101 => "macOS",
        0x8102 => "iOS",
        0x8201 => "Linux",
        0x8202 => "Solaris",
        0x8203 => "Android",
        0x8204 => "PS3",
        0x8205 => "Native Client",
        0x8206 => "Fuchsia",
        _ => "unknown",
    }
}

/// What a `PROCESSOR_ARCHITECTURE_*` value that is neither AMD64 nor ARM64
/// names.
fn architecture_name(architecture: u16) -> &'static str {
    match architecture {
        0 => "x86",
        5 => "ARM",
        6 => "IA-64",
        10 => "x86 on Win64",
        13 => "ARM on Win64",
        14 => "x86 on ARM64",
        _ => "unknown",
    }
}

/// The stream directory: each stream type's first location. A later stream
/// of a type already seen is ignored with a note.
struct Directory {
    streams: HashMap<u32, Location>,
}

impl Directory {
    fn stream<'a>(&self, data: &'a [u8], kind: u32, notes: &mut Vec<String>) -> Option<&'a [u8]> {
        let location = self.streams.get(&kind)?;
        let (rva, size) = (location.rva, location.data_size);
        let bytes = located(data, u64::from(rva), u64::from(size));
        if bytes.is_none() {
            notes.push(format!(
                "{} at {rva:#x} ({size:#x} bytes) leaves the file; ignored",
                stream_name(kind)
            ));
        }
        bytes
    }
}

fn stream_name(kind: u32) -> &'static str {
    match kind {
        THREAD_LIST_STREAM => "ThreadListStream",
        MODULE_LIST_STREAM => "ModuleListStream",
        MEMORY_LIST_STREAM => "MemoryListStream",
        EXCEPTION_STREAM => "ExceptionStream",
        SYSTEM_INFO_STREAM => "SystemInfoStream",
        MEMORY64_LIST_STREAM => "Memory64ListStream",
        HANDLE_DATA_STREAM => "HandleDataStream",
        FUNCTION_TABLE_STREAM => "FunctionTableStream",
        UNLOADED_MODULE_LIST_STREAM => "UnloadedModuleListStream",
        MISC_INFO_STREAM => "MiscInfoStream",
        MEMORY_INFO_LIST_STREAM => "MemoryInfoListStream",
        THREAD_INFO_LIST_STREAM => "ThreadInfoListStream",
        THREAD_NAME_LIST_STREAM => "ThreadNamesStream",
        _ => "stream",
    }
}

/// Whether `data` starts with the minidump signature. Kernel dumps start
/// with `PAGE`, so the two never collide.
pub fn is_minidump(data: &[u8]) -> bool {
    read_at::<u32>(data, 0) == Some(MINIDUMP_SIGNATURE)
}

/// A parsed minidump: what it records, and where in the file each captured
/// range of process memory is.
pub struct ParsedUserDump {
    pub info: UserDumpInfo,
    pub memory: Vec<MemoryRange>,
}

/// Parse a Windows user-mode minidump. Fails for a file that is not one, a
/// header or directory outside the file, a missing or unreadable
/// SystemInfoStream, a non-Windows platform (Breakpad/Crashpad), or an
/// architecture other than AMD64 and ARM64.
pub fn parse(data: &[u8]) -> Result<ParsedUserDump> {
    let header: RawHeader =
        read_at(data, 0).ok_or_else(|| invalid("minidump header is truncated"))?;
    if header.signature != MINIDUMP_SIGNATURE {
        return Err(invalid("not a minidump (no MDMP signature)"));
    }
    let version = header.version;
    if version as u16 != MINIDUMP_VERSION {
        return Err(invalid(format!(
            "unknown minidump version {:#06x}",
            version as u16
        )));
    }
    let count = header.number_of_streams;
    if count > MAX_STREAMS {
        return Err(invalid(format!("minidump claims {count} streams")));
    }
    let directory_rva = u64::from(header.stream_directory_rva);
    let mut notes = Vec::new();
    let mut streams = HashMap::new();
    for index in 0..u64::from(count) {
        let entry: RawDirectory = read_at(data, directory_rva + index * 12).ok_or_else(|| {
            invalid(format!(
                "stream directory at {directory_rva:#x} ({count} entries) leaves the file"
            ))
        })?;
        let kind = entry.stream_type;
        if kind == UNUSED_STREAM {
            continue;
        }
        if streams.contains_key(&kind) {
            notes.push(format!(
                "{} (type {kind}) appears more than once; the first is used",
                stream_name(kind)
            ));
            continue;
        }
        streams.insert(kind, entry.location);
    }
    let directory = Directory { streams };

    let (system, arch) = parse_system_info(data, &directory)?;
    let mut info = UserDumpInfo {
        time_date_stamp: header.time_date_stamp,
        flags: header.flags,
        arch,
        system,
        process_id: None,
        process_create_time: None,
        process_cpu_times: None,
        time_zone: None,
        build_string: None,
        threads: Vec::new(),
        modules: Vec::new(),
        unloaded_modules: Vec::new(),
        exception: None,
        handles: None,
        regions: None,
        function_tables: Vec::new(),
        notes: Vec::new(),
    };
    let mut memory = MemoryMap::default();

    if let Some(bytes) = directory.stream(data, MEMORY64_LIST_STREAM, &mut notes) {
        parse_memory64_list(data, bytes, &mut memory, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, MEMORY_LIST_STREAM, &mut notes) {
        parse_memory_list(data, bytes, &mut memory, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, THREAD_LIST_STREAM, &mut notes) {
        info.threads = parse_thread_list(data, bytes, arch, &mut memory, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, THREAD_INFO_LIST_STREAM, &mut notes) {
        merge_thread_info(bytes, &mut info.threads, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, THREAD_NAME_LIST_STREAM, &mut notes) {
        merge_thread_names(data, bytes, &mut info.threads, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, MODULE_LIST_STREAM, &mut notes) {
        info.modules = parse_module_list(data, bytes, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, UNLOADED_MODULE_LIST_STREAM, &mut notes) {
        info.unloaded_modules = parse_unloaded_modules(data, bytes, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, EXCEPTION_STREAM, &mut notes) {
        info.exception = parse_exception(data, bytes, arch, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, MISC_INFO_STREAM, &mut notes) {
        parse_misc_info(bytes, &mut info, &mut notes);
    }
    if let Some(bytes) = directory.stream(data, HANDLE_DATA_STREAM, &mut notes) {
        info.handles = Some(parse_handle_data(data, bytes, &mut notes));
    }
    if let Some(bytes) = directory.stream(data, MEMORY_INFO_LIST_STREAM, &mut notes) {
        info.regions = Some(parse_memory_info_list(bytes, &mut notes));
    }
    if let Some(bytes) = directory.stream(data, FUNCTION_TABLE_STREAM, &mut notes) {
        info.function_tables = parse_function_tables(data, bytes, arch, &memory, &mut notes);
    }

    info.notes = notes;
    Ok(ParsedUserDump {
        info,
        memory: memory.into_ranges(),
    })
}

fn parse_system_info(data: &[u8], directory: &Directory) -> Result<(UserSystemInfo, Arch)> {
    let location = directory.streams.get(&SYSTEM_INFO_STREAM).ok_or_else(|| {
        invalid("minidump has no SystemInfoStream, so its platform and architecture are unknown")
    })?;
    let raw: RawSystemInfo = located(data, u64::from(location.rva), u64::from(location.data_size))
        .and_then(|bytes| read_at(bytes, 0))
        .ok_or_else(|| invalid("SystemInfoStream is truncated or leaves the file"))?;
    let platform = raw.platform_id;
    if platform != PLATFORM_WIN32_NT {
        return Err(Error::UnsupportedDump(format!(
            "this is a {} minidump (platform {platform:#x}), as Breakpad and Crashpad write; \
             ntoseye opens Windows minidumps",
            platform_name(platform)
        )));
    }
    let architecture = raw.processor_architecture;
    let arch = match architecture {
        PROCESSOR_ARCHITECTURE_AMD64 => Arch::Amd64,
        PROCESSOR_ARCHITECTURE_ARM64 => Arch::Arm64,
        other => {
            return Err(Error::UnsupportedArchitecture(format!(
                "{} user-mode minidump (processor architecture {other})",
                architecture_name(other)
            )));
        }
    };
    let service_pack = match raw.csd_version_rva {
        0 => None,
        rva => read_string(data, u64::from(rva))
            .ok()
            .filter(|text| !text.is_empty()),
    };
    Ok((
        UserSystemInfo {
            processor_level: raw.processor_level,
            processor_revision: raw.processor_revision,
            number_of_processors: raw.number_of_processors,
            product_type: raw.product_type,
            major_version: raw.major_version,
            minor_version: raw.minor_version,
            build_number: raw.build_number,
            service_pack,
        },
        arch,
    ))
}

/// The captured ranges of process memory, kept disjoint: a range that
/// overlaps one already recorded only adds the part not yet covered, so the
/// earlier source wins. Memory64List is recorded first, then MemoryList, then
/// the thread stacks the thread list describes.
#[derive(Default)]
struct MemoryMap {
    /// `start -> (length, file offset)`.
    ranges: BTreeMap<u64, (u64, u64)>,
}

impl MemoryMap {
    fn add(&mut self, start: u64, length: u64, offset: u64) {
        let mut cursor = start;
        let end = start + length;
        while cursor < end {
            // The recorded range containing or after `cursor`.
            let containing = self
                .ranges
                .range(..=cursor)
                .next_back()
                .filter(|(base, (len, _))| cursor < **base + *len)
                .map(|(base, (len, _))| base + len);
            if let Some(covered_to) = containing {
                cursor = covered_to.min(end);
                continue;
            }
            let next = self
                .ranges
                .range(cursor..)
                .next()
                .map_or(end, |(base, _)| (*base).min(end));
            self.ranges
                .insert(cursor, (next - cursor, offset + (cursor - start)));
            cursor = next;
        }
    }

    fn into_ranges(self) -> Vec<MemoryRange> {
        self.ranges
            .into_iter()
            .map(|(start, (length, offset))| MemoryRange {
                start,
                length,
                offset,
            })
            .collect()
    }

    /// The `u32` at `address` in the captured memory recorded so far.
    fn read_u32(&self, data: &[u8], address: u64) -> Option<u32> {
        let (start, (length, offset)) = self.ranges.range(..=address).next_back()?;
        let within = address - start;
        (within.checked_add(4)? <= *length).then_some(())?;
        read_at(data, offset.checked_add(within)?)
    }
}

/// Record a captured range from its descriptor, clipped to the file. Returns
/// whether any of it was recorded.
fn add_range(
    memory: &mut MemoryMap,
    data: &[u8],
    start: u64,
    size: u64,
    offset: u64,
    what: &str,
    notes: &mut Vec<String>,
) -> bool {
    if size == 0 {
        return false;
    }
    let Some(last) = start.checked_add(size - 1) else {
        notes.push(format!(
            "{what} at {start:#x} ({size:#x} bytes) wraps the address space; ignored"
        ));
        return false;
    };
    let available = (data.len() as u64).saturating_sub(offset).min(size);
    if available == 0 {
        notes.push(format!(
            "{what} {start:#x}-{last:#x} is stored at {offset:#x}, outside the file; ignored"
        ));
        return false;
    }
    if available < size {
        notes.push(format!(
            "{what} {start:#x}-{last:#x} is cut short by the end of the file; {available:#x} of \
             {size:#x} bytes are readable"
        ));
    }
    // A range that ends at the very top of the address space has no
    // exclusive end; its last byte is left out rather than overflowing.
    let available = available.min(u64::MAX - start);
    memory.add(start, available, offset);
    true
}

fn parse_memory64_list(
    data: &[u8],
    stream: &[u8],
    memory: &mut MemoryMap,
    notes: &mut Vec<String>,
) {
    let (Some(count), Some(base_rva)) = (read_at::<u64>(stream, 0), read_at::<u64>(stream, 8))
    else {
        notes.push("Memory64ListStream header is truncated; its memory is not read".into());
        return;
    };
    if count > MAX_MEMORY_RANGES {
        notes.push(format!(
            "Memory64ListStream claims {count} ranges; its memory is not read"
        ));
        return;
    }
    let mut offset = base_rva;
    for index in 0..count {
        let Some(descriptor) = read_at::<RawMemoryDescriptor64>(stream, 16 + index * 16) else {
            notes.push(format!(
                "Memory64ListStream holds {index} of its {count} descriptors; the rest are not read"
            ));
            return;
        };
        let size = descriptor.data_size;
        add_range(
            memory,
            data,
            descriptor.start,
            size,
            offset,
            "memory range",
            notes,
        );
        match offset.checked_add(size) {
            Some(next) => offset = next,
            None => {
                notes.push(
                    "Memory64ListStream data overflows the file offset; the rest is not read"
                        .into(),
                );
                return;
            }
        }
    }
}

fn parse_memory_list(data: &[u8], stream: &[u8], memory: &mut MemoryMap, notes: &mut Vec<String>) {
    let Some(count) = read_at::<u32>(stream, 0) else {
        notes.push("MemoryListStream header is truncated; its memory is not read".into());
        return;
    };
    for index in 0..u64::from(count) {
        let Some(descriptor) = read_at::<RawMemoryDescriptor>(stream, 4 + index * 16) else {
            notes.push(format!(
                "MemoryListStream holds {index} of its {count} descriptors; the rest are not read"
            ));
            return;
        };
        let memory_location = descriptor.memory;
        add_range(
            memory,
            data,
            descriptor.start,
            u64::from(memory_location.data_size),
            u64::from(memory_location.rva),
            "memory range",
            notes,
        );
    }
}

/// The raw CONTEXT a location names, checked for the dump's architecture:
/// the full structure, the architecture flag, and the control and integer
/// registers a context needs to place a thread.
fn read_context(
    data: &[u8],
    location: Location,
    arch: Arch,
) -> std::result::Result<Vec<u8>, String> {
    let (size, flags_offset, arch_flag, required) = match arch {
        Arch::Amd64 => (
            amd64::CONTEXT_SIZE,
            amd64::OFFSET_CONTEXT_FLAGS,
            amd64::CONTEXT_AMD64,
            amd64::CONTEXT_CONTROL | amd64::CONTEXT_INTEGER,
        ),
        Arch::Arm64 => (
            arm64::CONTEXT_SIZE,
            arm64::OFFSET_CONTEXT_FLAGS,
            arm64::CONTEXT_ARM64,
            arm64::CONTEXT_CONTROL | arm64::CONTEXT_INTEGER,
        ),
    };
    let (rva, data_size) = (location.rva, location.data_size);
    if data_size == 0 && rva == 0 {
        return Err("the dump records no context".into());
    }
    if (data_size as usize) < size {
        return Err(format!(
            "the context is {data_size:#x} bytes, short of the {size:#x} an {} CONTEXT takes",
            arch.label()
        ));
    }
    let bytes = located(data, u64::from(rva), size as u64)
        .ok_or_else(|| format!("the context at {rva:#x} leaves the file"))?;
    let flags = read_at::<u32>(bytes, flags_offset as u64).unwrap_or(0);
    if flags & arch_flag == 0 {
        return Err(format!(
            "the context flags {flags:#x} do not mark an {} CONTEXT",
            arch.label()
        ));
    }
    if flags & required != required {
        return Err(format!(
            "the context flags {flags:#x} lack the control or integer registers"
        ));
    }
    Ok(bytes.to_vec())
}

fn parse_thread_list(
    data: &[u8],
    stream: &[u8],
    arch: Arch,
    memory: &mut MemoryMap,
    notes: &mut Vec<String>,
) -> Vec<UserThreadInfo> {
    let Some(count) = read_at::<u32>(stream, 0) else {
        notes.push("ThreadListStream header is truncated; no threads are listed".into());
        return Vec::new();
    };
    if count > MAX_THREADS {
        notes.push(format!(
            "ThreadListStream claims {count} threads; no threads are listed"
        ));
        return Vec::new();
    }
    let mut threads = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let Some(raw) = read_at::<RawThread>(stream, 4 + index * 48) else {
            notes.push(format!(
                "ThreadListStream holds {index} of its {count} threads; the rest are not listed"
            ));
            break;
        };
        let tid = raw.thread_id;
        let stack = raw.stack;
        let stack_location = stack.memory;
        let stack_size = u64::from(stack_location.data_size);
        let stack_range = add_range(
            memory,
            data,
            stack.start,
            stack_size,
            u64::from(stack_location.rva),
            &format!("thread {tid:#x} stack"),
            notes,
        )
        .then_some(CapturedStack {
            start: stack.start,
            size: stack_size,
        });
        threads.push(UserThreadInfo {
            tid,
            suspend_count: raw.suspend_count,
            priority_class: raw.priority_class,
            priority: raw.priority,
            teb: raw.teb,
            stack: stack_range,
            context: read_context(data, raw.context, arch),
            name: None,
            times: None,
        });
    }
    threads
}

fn merge_thread_info(stream: &[u8], threads: &mut [UserThreadInfo], notes: &mut Vec<String>) {
    let Some(header) = read_at::<RawSizedListHeader>(stream, 0) else {
        notes.push("ThreadInfoListStream header is truncated; ignored".into());
        return;
    };
    let (header_size, entry_size) = (header.size_of_header, header.size_of_entry);
    if (header_size as usize) < size_of::<RawSizedListHeader>()
        || (entry_size as usize) < size_of::<RawThreadInfo>()
    {
        notes.push(format!(
            "ThreadInfoListStream has header size {header_size:#x} and entry size \
             {entry_size:#x}, too small for its records; ignored"
        ));
        return;
    }
    let count = header.number_of_entries;
    for index in 0..u64::from(count) {
        let offset = u64::from(header_size) + index * u64::from(entry_size);
        let Some(raw) = read_at::<RawThreadInfo>(stream, offset) else {
            notes.push(format!(
                "ThreadInfoListStream holds {index} of its {count} entries; the rest are ignored"
            ));
            return;
        };
        let tid = raw.thread_id;
        if let Some(thread) = threads.iter_mut().find(|thread| thread.tid == tid) {
            thread.times = Some(UserThreadTimes {
                exit_status: raw.exit_status,
                create_time: raw.create_time,
                exit_time: raw.exit_time,
                kernel_time: raw.kernel_time,
                user_time: raw.user_time,
                start_address: raw.start_address,
                affinity: raw.affinity,
            });
        }
    }
}

fn merge_thread_names(
    data: &[u8],
    stream: &[u8],
    threads: &mut [UserThreadInfo],
    notes: &mut Vec<String>,
) {
    let Some(count) = read_at::<u32>(stream, 0) else {
        notes.push("ThreadNamesStream header is truncated; ignored".into());
        return;
    };
    for index in 0..u64::from(count) {
        let Some(raw) = read_at::<RawThreadName>(stream, 4 + index * 12) else {
            notes.push(format!(
                "ThreadNamesStream holds {index} of its {count} names; the rest are ignored"
            ));
            return;
        };
        let tid = raw.thread_id;
        let Some(thread) = threads.iter_mut().find(|thread| thread.tid == tid) else {
            continue;
        };
        match read_string(data, raw.name_rva) {
            Ok(name) if !name.is_empty() => thread.name = Some(name),
            Ok(_) => {}
            Err(error) => notes.push(format!("thread {tid:#x} name: {error}")),
        }
    }
}

/// `VS_FIXEDFILEINFO` version as `a.b.c.d`, `None` when the record is absent
/// (its signature is not 0xfeef04bd).
fn file_version(info: &[u32; 13]) -> Option<(String, String)> {
    if info[0] != 0xfeef_04bd {
        return None;
    }
    let format =
        |ms: u32, ls: u32| format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
    Some((format(info[2], info[3]), format(info[4], info[5])))
}

fn parse_module_list(data: &[u8], stream: &[u8], notes: &mut Vec<String>) -> Vec<UserModule> {
    let Some(count) = read_at::<u32>(stream, 0) else {
        notes.push("ModuleListStream header is truncated; no modules are listed".into());
        return Vec::new();
    };
    if count > MAX_MODULES {
        notes.push(format!(
            "ModuleListStream claims {count} modules; no modules are listed"
        ));
        return Vec::new();
    }
    let mut modules = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let Some(raw) = read_at::<RawModule>(stream, 4 + index * 108) else {
            notes.push(format!(
                "ModuleListStream holds {index} of its {count} modules; the rest are not listed"
            ));
            break;
        };
        let base = raw.base_of_image;
        let size = raw.size_of_image;
        if size == 0 || base.checked_add(u64::from(size)).is_none() {
            notes.push(format!(
                "module at {base:#x} has an invalid size {size:#x}; not listed"
            ));
            continue;
        }
        let path = match read_string(data, u64::from(raw.module_name_rva)) {
            Ok(path) if !path.is_empty() => path,
            Ok(_) => format!("module_{base:x}"),
            Err(error) => {
                notes.push(format!("module at {base:#x} name: {error}"));
                format!("module_{base:x}")
            }
        };
        let cv = raw.cv_record;
        let codeview = match (cv.rva, cv.data_size) {
            (0, _) | (_, 0) => None,
            (rva, size) if size as usize > MAX_CODEVIEW_BYTES => {
                notes.push(format!(
                    "{path}: CodeView record at {rva:#x} is {size:#x} bytes, more than \
                     {MAX_CODEVIEW_BYTES:#x}; ignored"
                ));
                None
            }
            (rva, size) => match located(data, u64::from(rva), u64::from(size)) {
                Some(bytes) => match decode_codeview(bytes) {
                    Ok(record) => Some(record),
                    Err(error) => {
                        notes.push(format!("{path}: {error}"));
                        None
                    }
                },
                None => {
                    notes.push(format!(
                        "{path}: CodeView record at {rva:#x} leaves the file; ignored"
                    ));
                    None
                }
            },
        };
        let version_info = raw.version_info;
        modules.push(UserModule {
            base,
            size,
            checksum: raw.check_sum,
            time_date_stamp: raw.time_date_stamp,
            path,
            version: file_version(&version_info),
            codeview,
        });
    }
    modules
}

fn parse_unloaded_modules(
    data: &[u8],
    stream: &[u8],
    notes: &mut Vec<String>,
) -> Vec<UnloadedModule> {
    let Some(header) = read_at::<RawSizedListHeader>(stream, 0) else {
        notes.push("UnloadedModuleListStream header is truncated; ignored".into());
        return Vec::new();
    };
    let (header_size, entry_size) = (header.size_of_header, header.size_of_entry);
    if (header_size as usize) < size_of::<RawSizedListHeader>()
        || (entry_size as usize) < size_of::<RawUnloadedModule>()
    {
        notes.push(format!(
            "UnloadedModuleListStream has header size {header_size:#x} and entry size \
             {entry_size:#x}, too small for its records; ignored"
        ));
        return Vec::new();
    }
    let count = header.number_of_entries.min(MAX_MODULES);
    let mut modules = Vec::new();
    for index in 0..u64::from(count) {
        let offset = u64::from(header_size) + index * u64::from(entry_size);
        let Some(raw) = read_at::<RawUnloadedModule>(stream, offset) else {
            notes.push(format!(
                "UnloadedModuleListStream holds {index} of its {count} entries; the rest are \
                 ignored"
            ));
            break;
        };
        let base = raw.base_of_image;
        let name = read_string(data, u64::from(raw.module_name_rva))
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("module_{base:x}"));
        modules.push(UnloadedModule {
            base,
            size: raw.size_of_image,
            checksum: raw.check_sum,
            time_date_stamp: raw.time_date_stamp,
            name,
        });
    }
    modules
}

fn parse_exception(
    data: &[u8],
    stream: &[u8],
    arch: Arch,
    notes: &mut Vec<String>,
) -> Option<UserException> {
    let Some(raw) = read_at::<RawException>(stream, 0) else {
        notes.push("ExceptionStream is truncated; the exception is not shown".into());
        return None;
    };
    let count = raw.number_parameters;
    let information = raw.information;
    let parameters = information[..(count as usize).min(information.len())].to_vec();
    let thread_id = raw.thread_id;
    Some(UserException {
        thread_id,
        code: raw.code,
        flags: raw.flags,
        record: raw.record,
        address: raw.address,
        parameters,
        context: read_context(data, raw.context, arch),
    })
}

fn parse_misc_info(stream: &[u8], info: &mut UserDumpInfo, notes: &mut Vec<String>) {
    let Some(raw) = read_at::<RawMiscInfo>(stream, 0) else {
        notes.push("MiscInfoStream is truncated; ignored".into());
        return;
    };
    let size = (raw.size_of_info as usize).min(stream.len());
    let flags = raw.flags1;
    if flags & MISC1_PROCESS_ID != 0 {
        info.process_id = Some(raw.process_id);
    }
    if flags & MISC1_PROCESS_TIMES != 0 {
        info.process_create_time = Some(raw.process_create_time);
        info.process_cpu_times = Some((raw.process_user_time, raw.process_kernel_time));
    }
    if flags & MISC3_TIMEZONE != 0 && size >= MISC_INFO_TIME_ZONE + TIME_ZONE_INFORMATION_SIZE {
        info.time_zone = parse_time_zone(
            read_at(stream, MISC_INFO_TIME_ZONE_ID as u64).unwrap_or(0),
            &stream[MISC_INFO_TIME_ZONE..MISC_INFO_TIME_ZONE + TIME_ZONE_INFORMATION_SIZE],
        );
    }
    let build_end = MISC_INFO_BUILD_STRING + MISC_INFO_BUILD_STRING_UNITS * 2;
    if flags & MISC4_BUILDSTRING != 0 && size >= build_end {
        let build = utf16le_nul_terminated(&stream[MISC_INFO_BUILD_STRING..build_end]);
        info.build_string = (!build.is_empty()).then_some(build);
    }
}

/// The zone a `TIME_ZONE_INFORMATION` describes in the period `id` names:
/// `Bias`, plus `StandardBias` or `DaylightBias`. An unknown period
/// (`TIME_ZONE_ID_UNKNOWN`, no daylight saving) takes the standard one.
fn parse_time_zone(id: u32, zone: &[u8]) -> Option<UserTimeZone> {
    // Bias, StandardName[32], StandardDate, StandardBias, DaylightName[32],
    // DaylightDate, DaylightBias.
    let bias: i32 = read_at(zone, 0)?;
    let (name, extra) = match id {
        TIME_ZONE_ID_UNKNOWN | TIME_ZONE_ID_STANDARD => (
            utf16le_nul_terminated(zone.get(4..68)?),
            read_at::<i32>(zone, 84)?,
        ),
        TIME_ZONE_ID_DAYLIGHT => (
            utf16le_nul_terminated(zone.get(88..152)?),
            read_at::<i32>(zone, 168)?,
        ),
        _ => return None,
    };
    Some(UserTimeZone {
        bias: bias.checked_add(extra)?,
        name,
    })
}

fn parse_handle_data(data: &[u8], stream: &[u8], notes: &mut Vec<String>) -> Vec<UserHandle> {
    let Some(header) = read_at::<RawHandleDataHeader>(stream, 0) else {
        notes.push("HandleDataStream header is truncated; no handles are listed".into());
        return Vec::new();
    };
    let (header_size, entry_size) = (header.size_of_header, header.size_of_descriptor);
    if (header_size as usize) < size_of::<RawHandleDataHeader>()
        || (entry_size as usize) < size_of::<RawHandleDescriptor>()
    {
        notes.push(format!(
            "HandleDataStream has header size {header_size:#x} and descriptor size \
             {entry_size:#x}, too small for its records; no handles are listed"
        ));
        return Vec::new();
    }
    let count = header.number_of_descriptors.min(MAX_HANDLES);
    let string = |rva: u32, what: &str, handle: u64, notes: &mut Vec<String>| match rva {
        0 => None,
        rva => match read_string(data, u64::from(rva)) {
            Ok(text) => (!text.is_empty()).then_some(text),
            Err(error) => {
                notes.push(format!("handle {handle:#x} {what}: {error}"));
                None
            }
        },
    };
    let mut handles = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let offset = u64::from(header_size) + index * u64::from(entry_size);
        let Some(raw) = read_at::<RawHandleDescriptor>(stream, offset) else {
            notes.push(format!(
                "HandleDataStream holds {index} of its {count} descriptors; the rest are not \
                 listed"
            ));
            break;
        };
        let handle = raw.handle;
        handles.push(UserHandle {
            handle,
            type_name: string(raw.type_name_rva, "type name", handle, notes),
            object_name: string(raw.object_name_rva, "object name", handle, notes),
            attributes: raw.attributes,
            granted_access: raw.granted_access,
            handle_count: raw.handle_count,
            pointer_count: raw.pointer_count,
        });
    }
    handles
}

fn parse_memory_info_list(stream: &[u8], notes: &mut Vec<String>) -> Vec<MemoryRegion> {
    let Some(header) = read_at::<RawMemoryInfoListHeader>(stream, 0) else {
        notes.push("MemoryInfoListStream header is truncated; no regions are listed".into());
        return Vec::new();
    };
    let (header_size, entry_size) = (header.size_of_header, header.size_of_entry);
    if (header_size as usize) < size_of::<RawMemoryInfoListHeader>()
        || (entry_size as usize) < size_of::<RawMemoryInfo>()
    {
        notes.push(format!(
            "MemoryInfoListStream has header size {header_size:#x} and entry size \
             {entry_size:#x}, too small for its records; no regions are listed"
        ));
        return Vec::new();
    }
    let count = header.number_of_entries.min(MAX_MEMORY_RANGES);
    let mut regions = Vec::new();
    for index in 0..count {
        let offset = u64::from(header_size) + index * u64::from(entry_size);
        let Some(raw) = read_at::<RawMemoryInfo>(stream, offset) else {
            notes.push(format!(
                "MemoryInfoListStream holds {index} of its {count} regions; the rest are not \
                 listed"
            ));
            break;
        };
        let (base, size) = (raw.base_address, raw.region_size);
        if size == 0 || base.checked_add(size - 1).is_none() {
            notes.push(format!(
                "memory region at {base:#x} has an invalid size {size:#x}; not listed"
            ));
            continue;
        }
        regions.push(MemoryRegion {
            base,
            allocation_base: raw.allocation_base,
            allocation_protect: raw.allocation_protect,
            size,
            state: raw.state,
            protect: raw.protect,
            kind: raw.kind,
        });
    }
    regions.sort_by_key(|region| region.base);
    let before = regions.len();
    let mut end = 0u64;
    regions.retain(|region| {
        let keep = region.base >= end;
        if keep {
            end = region.base + region.size;
        }
        keep
    });
    if regions.len() < before {
        notes.push(format!(
            "MemoryInfoListStream has {} regions overlapping earlier ones; they are not listed",
            before - regions.len()
        ));
    }
    regions
}

/// The dynamic function tables of `FunctionTableStream`: the unwind entries
/// for code outside every module, such as JIT-compiled code. An ARM64
/// entry records no end; its length is in its packed unwind data, or in its
/// `.xdata` header in process memory, read from `memory`.
fn parse_function_tables(
    data: &[u8],
    stream: &[u8],
    arch: Arch,
    memory: &MemoryMap,
    notes: &mut Vec<String>,
) -> Vec<FunctionTable> {
    let Some(header) = read_at::<RawFunctionTableHeader>(stream, 0) else {
        notes.push("FunctionTableStream header is truncated; its tables are not used".into());
        return Vec::new();
    };
    let runtime_function_size = match arch {
        Arch::Amd64 => AMD64_RUNTIME_FUNCTION_SIZE,
        Arch::Arm64 => ARM64_RUNTIME_FUNCTION_SIZE,
    };
    let (header_size, descriptor_size, native_size, entry_size) = (
        header.size_of_header,
        header.size_of_descriptor,
        header.size_of_native_descriptor,
        header.size_of_function_entry,
    );
    if (header_size as usize) < size_of::<RawFunctionTableHeader>()
        || (descriptor_size as usize) < size_of::<RawFunctionTableDescriptor>()
        || entry_size < runtime_function_size
    {
        notes.push(format!(
            "FunctionTableStream has header size {header_size:#x}, descriptor size \
             {descriptor_size:#x}, and entry size {entry_size:#x}, too small for its records; \
             its tables are not used"
        ));
        return Vec::new();
    }
    let count = header.number_of_descriptors.min(MAX_FUNCTION_TABLES);
    let mut offset = u64::from(header_size) + u64::from(header.size_of_align_pad);
    let mut tables = Vec::new();
    for index in 0..count {
        let Some(raw) = read_at::<RawFunctionTableDescriptor>(stream, offset) else {
            notes.push(format!(
                "FunctionTableStream holds {index} of its {count} tables; the rest are not used"
            ));
            break;
        };
        let (minimum, maximum, base) = (raw.minimum_address, raw.maximum_address, raw.base_address);
        let entries_at = offset + u64::from(descriptor_size) + u64::from(native_size);
        let entry_count = u64::from(raw.entry_count);
        let entries_end = entries_at + entry_count * u64::from(entry_size);
        if entries_end > stream.len() as u64 {
            notes.push(format!(
                "function table {minimum:#x}-{maximum:#x} has {entry_count} entries, more than \
                 the stream holds; it and the tables after it are not used"
            ));
            break;
        }
        offset = entries_end + u64::from(raw.size_of_align_pad);
        if minimum >= maximum {
            notes.push(format!(
                "function table {minimum:#x}-{maximum:#x} covers no addresses; not used"
            ));
            continue;
        }
        let mut entries: Vec<DynamicFunction> = (0..entry_count)
            .filter_map(|entry| {
                let at = entries_at + entry * u64::from(entry_size);
                match arch {
                    Arch::Amd64 => Some(DynamicFunction {
                        begin: read_at(stream, at)?,
                        end: read_at(stream, at + 4)?,
                        unwind_data: read_at(stream, at + 8)?,
                    }),
                    Arch::Arm64 => {
                        let begin: u32 = read_at(stream, at)?;
                        let unwind_data: u32 = read_at(stream, at + 4)?;
                        let instructions = match unwind_data & 0b11 {
                            0 => {
                                let xdata = base.checked_add(u64::from(unwind_data))?;
                                memory.read_u32(data, xdata)? & 0x3ffff
                            }
                            1 | 2 => (unwind_data >> 2) & 0x7ff,
                            _ => return None,
                        };
                        Some(DynamicFunction {
                            begin,
                            end: begin.checked_add(instructions.checked_mul(4)?)?,
                            unwind_data,
                        })
                    }
                }
            })
            .filter(|entry| entry.begin < entry.end)
            .collect();
        let malformed = entry_count as usize - entries.len();
        entries.sort_by_key(|entry| entry.begin);
        let mut end = 0u32;
        entries.retain(|entry| {
            let keep = entry.begin >= end;
            if keep {
                end = entry.end;
            }
            keep
        });
        let dropped = entry_count as usize - entries.len();
        if dropped > 0 {
            notes.push(format!(
                "function table {minimum:#x}-{maximum:#x}: {dropped} of its {entry_count} entries \
                 are empty, overlap another, or have unwind data the dump did not capture \
                 ({malformed} empty or not captured); they are not used"
            ));
        }
        tables.push(FunctionTable {
            minimum,
            maximum,
            base,
            entries,
        });
    }
    tables
}
