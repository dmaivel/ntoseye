use crate::{
    backend::MemoryOps,
    dmp::DmpInfo,
    error::{Error, Result},
    memory::{self, AddressSpace, DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::{
        DownloadJob, FieldInfo, ModuleSymbolDiscovery, ModuleSymbolLoad, ModuleSymbolSource,
        ModuleSymbolStatus, ParsedType, SymbolIndexDiagnostic, SymbolStore, TypeInfo,
        download_jobs_parallel, le_uint,
    },
    target::object::DriverObjectInfo,
    target::{ListCursor, ListTermination},
    types::*,
};
use indicatif::{ProgressBar, ProgressStyle};
use pelite::{PeFile, PeView, Wrap, image::IMAGE_DIRECTORY_ENTRY_EXPORT};
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zerocopy::{FromBytes, IntoBytes};

/// `EPROCESS.ImageFileName` capacity: the kernel keeps this many bytes of the
/// image name, unterminated when the name is at least this long.
const IMAGE_FILE_NAME_LEN: usize = 15;
const MAX_LOADER_MODULES: usize = 1000;

/// A process's identity and the root (`dtb`) of its address space.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub name: String,
    pub dtb: Dtb,
    pub eprocess_va: VirtAddr,
    /// The 32-bit PEB of a WOW64 process (`_EPROCESS.WoW64Process`), `None`
    /// for a native process.
    pub wow64_peb: Option<VirtAddr>,
}

impl ProcessInfo {
    pub fn is_wow64(&self) -> bool {
        self.wow64_peb.is_some()
    }
}

/// module metadata from PEB LDR list
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub short_name: String,
    pub path: Option<String>,
    pub base_address: VirtAddr,
    pub size: u32,
    /// From a WOW64 process's 32-bit loader list: x86 code, 4-byte pointers.
    pub is_32bit: bool,
    pub entry_point: Option<VirtAddr>,
    pub time_date_stamp: Option<u32>,
    pub checksum: Option<u32>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
}

impl ModuleInfo {
    pub fn new(name: String, base_address: VirtAddr, size: u32) -> Self {
        let short_name = Self::derive_short_name(&name);
        Self {
            name,
            short_name,
            path: None,
            base_address,
            size,
            is_32bit: false,
            entry_point: None,
            time_date_stamp: None,
            checksum: None,
            file_version: None,
            product_version: None,
        }
    }

    pub fn with_time_date_stamp(mut self, tds: u32) -> Self {
        self.time_date_stamp = Some(tds);
        self
    }

    pub fn with_checksum(mut self, cs: u32) -> Self {
        self.checksum = Some(cs);
        self
    }

    pub fn with_version_info(mut self, file_ver: String, product_ver: String) -> Self {
        self.file_version = Some(file_ver);
        self.product_version = Some(product_ver);
        self
    }

    pub fn derive_short_name(name: &str) -> String {
        let filename = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let without_ext = filename
            .rsplit_once('.')
            .map(|(base, _)| base)
            .unwrap_or(filename);

        let lowered = without_ext.to_lowercase();
        match lowered.as_str() {
            "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp" => "nt".to_string(),
            _ => lowered,
        }
    }

    pub fn end_address(&self) -> VirtAddr {
        VirtAddr(self.base_address.0.saturating_add(self.size as u64))
    }

    pub fn contains_address(&self, address: VirtAddr) -> bool {
        address.0 >= self.base_address.0 && address.0 < self.end_address().0
    }
}

/// One export recovered from a module's mapped PE export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleExportInfo {
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: Option<VirtAddr>,
    pub forwarder: Option<String>,
}

/// Native and optional WOW64 loader-list results for one process.
#[derive(Debug, Clone)]
pub struct ProcessModulesDetail {
    pub modules: Vec<ModuleInfo>,
    pub termination: ListTermination,
    pub wow64_termination: Option<ListTermination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSymbolDiagnostic {
    pub module: String,
    pub phase: &'static str,
    pub compiland: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleSymbolLoadReport {
    pub total: usize,
    pub loaded: usize,
    /// Symbol-bearing modules removed from this DTB since the previous refresh.
    pub unloaded: usize,
    pub no_pdb: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Handed to the background fetcher; not yet loaded or failed.
    pub fetching: usize,
    pub diagnostic_count: usize,
    pub diagnostics: Vec<ModuleSymbolDiagnostic>,
}

impl ModuleSymbolLoadReport {
    fn new(total: usize) -> Self {
        Self {
            total,
            ..Self::default()
        }
    }

    fn record_status(&mut self, status: &ModuleSymbolStatus) {
        match status {
            ModuleSymbolStatus::Loaded => {
                self.loaded += 1;
            }
            ModuleSymbolStatus::MissingDebugInfo => {
                self.no_pdb += 1;
            }
            ModuleSymbolStatus::Skipped => {
                self.skipped += 1;
            }
            ModuleSymbolStatus::Failed(_) => {
                self.failed += 1;
            }
            ModuleSymbolStatus::Fetching => {
                self.fetching += 1;
            }
        }
    }

    fn record_diagnostics(&mut self, module: &str, diagnostics: Vec<SymbolIndexDiagnostic>) {
        const REPORT_DIAGNOSTIC_LIMIT: usize = 64;
        self.diagnostic_count += diagnostics.len();
        let remaining = REPORT_DIAGNOSTIC_LIMIT.saturating_sub(self.diagnostics.len());
        self.diagnostics
            .extend(diagnostics.into_iter().take(remaining).map(|diagnostic| {
                ModuleSymbolDiagnostic {
                    module: module.to_string(),
                    phase: diagnostic.phase,
                    compiland: diagnostic.compiland,
                    message: diagnostic.message,
                }
            }));
    }

    pub fn failed_count(&self) -> usize {
        self.failed
    }

    /// Fold in a follow-up pass over modules already counted in `total`.
    fn absorb(&mut self, other: Self) {
        self.loaded += other.loaded;
        self.unloaded += other.unloaded;
        self.no_pdb += other.no_pdb;
        self.skipped += other.skipped;
        self.failed += other.failed;
        self.fetching += other.fetching;
        self.diagnostic_count += other.diagnostic_count;
        self.diagnostics.extend(other.diagnostics);
    }
}

/// What symbol discovery found for a batch of modules, before any file or
/// network work (see [`Guest::plan_module_symbol_loads`]).
#[derive(Default)]
struct ModuleSymbolPlan {
    /// PDB already on disk; only indexing remains.
    ready: Vec<ModuleSymbolLoad>,
    /// PDB identity known; the file must be acquired.
    downloads: Vec<ModuleSymbolLoad>,
    /// Headers unreadable in memory; the image must be fetched to learn the
    /// PDB identity, then treated as `downloads`.
    image_jobs: Vec<(DownloadJob, ModuleInfo)>,
}

impl ModuleSymbolPlan {
    fn queue(&mut self, symbols: &SymbolStore, load: ModuleSymbolLoad) {
        // Parsed already, or on disk with the right identity: no source to
        // consult, so it is never a fetch (which the stop render defers).
        if symbols.has_matching_pdb(&load.job) || load.job.cached_pdb_matches() {
            self.ready.push(load);
        } else {
            self.downloads.push(load);
        }
    }

    /// Split off everything that needs the network, leaving `ready`.
    fn take_fetches(&mut self) -> Self {
        Self {
            ready: Vec::new(),
            downloads: std::mem::take(&mut self.downloads),
            image_jobs: std::mem::take(&mut self.image_jobs),
        }
    }

    fn absorb(&mut self, other: Self) {
        self.ready.extend(other.ready);
        self.downloads.extend(other.downloads);
        self.image_jobs.extend(other.image_jobs);
    }

    fn needs_fetch(&self) -> bool {
        !self.downloads.is_empty() || !self.image_jobs.is_empty()
    }

    fn len(&self) -> usize {
        self.ready.len() + self.downloads.len() + self.image_jobs.len()
    }

    fn modules(&self) -> impl Iterator<Item = &ModuleInfo> {
        self.ready
            .iter()
            .chain(&self.downloads)
            .map(|load| &load.module)
            .chain(self.image_jobs.iter().map(|(_, module)| module))
    }

    fn module_names(&self) -> Vec<String> {
        self.modules().map(|module| module.name.clone()).collect()
    }
}

/// A module image addressed by RVA. An on-disk image is complete; an image
/// read from guest memory is demand-read in [`IMAGE_BLOCK`]-sized blocks and
/// keeps every block it has read, so a stack walk costs the blocks its
/// lookups touch rather than the whole `.pdata`/`.rdata` of the module,
/// which for a kernel over a KD serial link is megabytes.
pub struct PeImage {
    size: usize,
    body: ImageBody,
}

enum ImageBody {
    Complete(Vec<u8>),
    Lazy(LazyImage),
}

/// One block is one KD memory request, and a block never straddles a page,
/// so a block is either readable or not as a whole.
const IMAGE_BLOCK: usize = 0x800;

type ImageReader = Box<dyn Fn(usize, &mut [u8]) -> Result<()> + Send + Sync>;

struct LazyImage {
    /// The header page, read up front; what a `PeView` is built on.
    headers: Box<[u8]>,
    /// Reads `buf.len()` bytes of the image at an RVA.
    read: ImageReader,
    /// Blocks by index. A block the target refused (paged out) is not
    /// recorded, so it is asked for again once the target has run.
    blocks: Mutex<HashMap<usize, Box<[u8]>>>,
}

impl std::fmt::Debug for PeImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeImage")
            .field("size", &self.size)
            .field("complete", &self.is_complete())
            .finish()
    }
}

impl PeImage {
    /// Wrap fully-available bytes (e.g. a complete on-disk image).
    pub fn complete(bytes: Vec<u8>) -> Self {
        Self {
            size: bytes.len(),
            body: ImageBody::Complete(bytes),
        }
    }

    /// Bytes a `PeView` may be built on: the whole image when complete,
    /// otherwise the header page. Directories past the headers are not in
    /// here; read them through [`read`](Self::read).
    pub fn headers(&self) -> &[u8] {
        match &self.body {
            ImageBody::Complete(bytes) => bytes,
            ImageBody::Lazy(lazy) => &lazy.headers,
        }
    }

    /// Whether every byte is known up front (an on-disk image); a lazy image
    /// can always still hit a paged-out block.
    pub fn is_complete(&self) -> bool {
        matches!(self.body, ImageBody::Complete(_))
    }

    /// Whether `[at, at+len)` is in bounds and readable from the target.
    pub fn is_present(&self, at: usize, len: usize) -> bool {
        self.read(at, len).is_some()
    }

    /// `len` bytes at RVA `at`, or `None` when out of bounds or any block of
    /// the range is paged out. Blocks are fetched on first use.
    pub fn read(&self, at: usize, len: usize) -> Option<Cow<'_, [u8]>> {
        let end = at.checked_add(len)?;
        if end > self.size {
            return None;
        }
        match &self.body {
            ImageBody::Complete(bytes) => Some(Cow::Borrowed(&bytes[at..end])),
            ImageBody::Lazy(lazy) => {
                if len == 0 {
                    return Some(Cow::Borrowed(&[]));
                }
                let mut blocks = lazy.blocks.lock().unwrap_or_else(PoisonError::into_inner);
                let mut out = Vec::with_capacity(len);
                for index in at / IMAGE_BLOCK..=(end - 1) / IMAGE_BLOCK {
                    let block = match blocks.entry(index) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(lazy.fetch(index, self.size)?),
                    };
                    let start = at.saturating_sub(index * IMAGE_BLOCK);
                    let stop = (end - index * IMAGE_BLOCK).min(block.len());
                    out.extend_from_slice(&block[start..stop]);
                }
                Some(Cow::Owned(out))
            }
        }
    }
}

impl LazyImage {
    fn fetch(&self, index: usize, size: usize) -> Option<Box<[u8]>> {
        let start = index * IMAGE_BLOCK;
        let mut block = vec![0u8; IMAGE_BLOCK.min(size - start)];
        (self.read)(start, &mut block).ok()?;
        Some(block.into_boxed_slice())
    }
}

/// Bytes of a module's headers read before the section table's end is known.
/// A normally linked image keeps its DOS stub, NT headers, and section table
/// well inside this; only an image whose table runs past it costs a second
/// read.
const PE_HEADER_PROBE: usize = 0x400;

/// Where the section table of the headers in `probe` ends, or `None` when
/// the NT headers themselves extend past the probe. A buffer that is not a
/// PE ends at the probe: reading more of it changes nothing.
pub fn pe_headers_end(probe: &[u8]) -> Option<usize> {
    if probe.len() < 0x40 || &probe[..2] != b"MZ" {
        return Some(probe.len());
    }
    let e_lfanew = u32::from_le_bytes(probe[0x3c..0x40].try_into().unwrap()) as usize;
    let nt = probe.get(e_lfanew..e_lfanew.checked_add(24)?)?;
    if &nt[..4] != b"PE\0\0" {
        return Some(probe.len());
    }
    let sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let optional = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    Some(e_lfanew + 24 + optional + sections * 40)
}

/// Read a module's headers into a page-sized buffer, as `PeView` wants them,
/// with a probe-sized first read and a second only when the section table
/// extends past it. The page tail beyond the table stays zero; nothing in it
/// is consulted.
pub fn read_pe_header_page<B: MemoryOps<PhysAddr>>(
    base_address: VirtAddr,
    memory: &memory::AddressSpace<'_, B>,
) -> Result<[u8; PAGE_SIZE]> {
    read_pe_header_page_with(&|address, buf| memory.read_bytes(base_address + address, buf))
}

/// [`read_pe_header_page`] over a reader addressed by RVA.
fn read_pe_header_page_with(
    read: &dyn Fn(u64, &mut [u8]) -> Result<()>,
) -> Result<[u8; PAGE_SIZE]> {
    let mut header_buf = [0u8; PAGE_SIZE];
    read(0, &mut header_buf[..PE_HEADER_PROBE])?;
    let end = pe_headers_end(&header_buf[..PE_HEADER_PROBE])
        .unwrap_or(PAGE_SIZE)
        .min(PAGE_SIZE);
    if end > PE_HEADER_PROBE {
        read(
            PE_HEADER_PROBE as u64,
            &mut header_buf[PE_HEADER_PROBE..end],
        )?;
    }
    Ok(header_buf)
}

/// `SizeOfImage` of either PE format.
pub fn size_of_image(view: &PeView<'_>) -> u32 {
    match view.optional_header() {
        Wrap::T32(header) => header.SizeOfImage,
        Wrap::T64(header) => header.SizeOfImage,
    }
}

/// Preferred `ImageBase` of either PE format.
pub fn image_base(view: &PeView<'_>) -> u64 {
    match view.optional_header() {
        Wrap::T32(header) => u64::from(header.ImageBase),
        Wrap::T64(header) => header.ImageBase,
    }
}

/// Open a module image in guest memory: the headers are read now, the rest
/// on demand through `read`, which reads `buf.len()` bytes at a virtual
/// address of the module's address space.
pub fn read_pe_image(
    base_address: VirtAddr,
    read: impl Fn(VirtAddr, &mut [u8]) -> Result<()> + Send + Sync + 'static,
) -> Result<PeImage> {
    let headers = read_pe_header_page_with(&|address, buf| read(base_address + address, buf))?;
    let size = size_of_image(&PeView::from_bytes(&headers)?) as usize;
    Ok(PeImage {
        size,
        body: ImageBody::Lazy(LazyImage {
            headers: Box::new(headers),
            read: Box::new(move |rva, buf| read(base_address + rva as u64, buf)),
            blocks: Mutex::new(HashMap::new()),
        }),
    })
}

fn read_export_bytes<'a>(
    image: &'a PeImage,
    base: VirtAddr,
    rva: u32,
    length: usize,
) -> Result<Cow<'a, [u8]>> {
    let start = rva as usize;
    let end = start
        .checked_add(length)
        .filter(|&end| end <= image.size)
        .ok_or_else(|| Error::DebugInfo("PE export data lies outside SizeOfImage".into()))?;
    image
        .read(start, end - start)
        .ok_or(Error::BadVirtualAddress(base + u64::from(rva)))
}

fn read_export_string(image: &PeImage, base: VirtAddr, rva: u32) -> Result<String> {
    const CHUNK: usize = 128;
    const MAX_LENGTH: usize = 4096;
    let mut bytes = Vec::new();
    let mut offset = rva as usize;
    while bytes.len() < MAX_LENGTH {
        let length = CHUNK
            .min(MAX_LENGTH - bytes.len())
            .min(image.size.saturating_sub(offset));
        if length == 0 {
            break;
        }
        let chunk = read_export_bytes(image, base, offset as u32, length)?;
        if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk);
        offset = offset.saturating_add(length);
    }
    Err(Error::DebugInfo(format!(
        "unterminated or overlong PE export string at {:#x}",
        base.0.saturating_add(u64::from(rva))
    )))
}

/// Read named and ordinal-only exports from a mapped module image. The image
/// remains lazy: only the export directory, address tables, and strings are
/// fetched, and an unreadable mapped page remains a memory-access error.
pub fn read_pe_exports(image: &PeImage, base: VirtAddr) -> Result<Vec<ModuleExportInfo>> {
    const DIRECTORY_SIZE: usize = 40;
    const MAX_EXPORTS: usize = 1_000_000;

    let headers = PeView::from_bytes(image.headers())?;
    let Some(directory) = headers.data_directory().get(IMAGE_DIRECTORY_ENTRY_EXPORT) else {
        return Ok(Vec::new());
    };
    let directory_rva = directory.VirtualAddress;
    let directory_size = directory.Size;
    // Most drivers export nothing: the directory entry is present but zero.
    if directory_rva == 0 && directory_size == 0 {
        return Ok(Vec::new());
    }
    if directory_size < DIRECTORY_SIZE as u32 {
        return Err(Error::DebugInfo("truncated PE export directory".into()));
    }
    let data = read_export_bytes(image, base, directory_rva, DIRECTORY_SIZE)?;
    let u32_at = |offset: usize| {
        u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .expect("fixed export field"),
        )
    };
    let ordinal_base = u32_at(16);
    let function_count = u32_at(20) as usize;
    let name_count = u32_at(24) as usize;
    let functions_rva = u32_at(28);
    let names_rva = u32_at(32);
    let ordinals_rva = u32_at(36);
    if function_count > MAX_EXPORTS || name_count > MAX_EXPORTS {
        return Err(Error::DebugInfo(
            "PE export count exceeds the safety bound".into(),
        ));
    }

    let functions = read_export_bytes(image, base, functions_rva, function_count * 4)?;
    let names = read_export_bytes(image, base, names_rva, name_count * 4)?;
    let ordinals = read_export_bytes(image, base, ordinals_rva, name_count * 2)?;
    let mut names_by_function: HashMap<usize, Vec<String>> = HashMap::new();
    for index in 0..name_count {
        let name_rva = u32::from_le_bytes(
            names[index * 4..index * 4 + 4]
                .try_into()
                .expect("fixed export name RVA"),
        );
        let function_index = usize::from(u16::from_le_bytes(
            ordinals[index * 2..index * 2 + 2]
                .try_into()
                .expect("fixed export ordinal index"),
        ));
        if function_index >= function_count {
            return Err(Error::DebugInfo(format!(
                "PE export name index {function_index} exceeds function count {function_count}"
            )));
        }
        names_by_function
            .entry(function_index)
            .or_default()
            .push(read_export_string(image, base, name_rva)?);
    }

    let mut exports = Vec::new();
    let forwarder_end = directory_rva.saturating_add(directory_size);
    for index in 0..function_count {
        let function_rva = u32::from_le_bytes(
            functions[index * 4..index * 4 + 4]
                .try_into()
                .expect("fixed export function RVA"),
        );
        if function_rva == 0 {
            continue;
        }
        let ordinal = ordinal_base
            .checked_add(index as u32)
            .ok_or_else(|| Error::DebugInfo("PE export ordinal overflow".into()))?;
        let forwarder = (function_rva >= directory_rva && function_rva < forwarder_end)
            .then(|| read_export_string(image, base, function_rva))
            .transpose()?;
        let address = forwarder
            .is_none()
            .then_some(VirtAddr(base.0.saturating_add(u64::from(function_rva))));
        let names = names_by_function.remove(&index).unwrap_or_default();
        if names.is_empty() {
            exports.push(ModuleExportInfo {
                name: None,
                ordinal,
                address,
                forwarder,
            });
        } else {
            exports.extend(names.into_iter().map(|name| ModuleExportInfo {
                name: Some(name),
                ordinal,
                address,
                forwarder: forwarder.clone(),
            }));
        }
    }
    Ok(exports)
}

/// Name of the PE section containing `address` within the image loaded at
/// `base` (e.g. `.text`), or `None` if `address` isn't in a section or `base`
/// isn't a readable PE. Reads only the header page, like `read_pe_image`'s
/// prologue.
pub fn section_name_at<'a, B: MemoryOps<PhysAddr>>(
    memory: &memory::AddressSpace<'a, B>,
    base: VirtAddr,
    address: VirtAddr,
) -> Option<String> {
    let rva = u32::try_from(address.0.checked_sub(base.0)?).ok()?;
    let header_buf = read_pe_header_page(base, memory).ok()?;
    let view = PeView::from_bytes(&header_buf).ok()?;
    for section in view.section_headers() {
        let va = section.VirtualAddress;
        let size = section.VirtualSize.max(section.SizeOfRawData);
        if rva >= va && rva < va.saturating_add(size) {
            return section.name().ok().map(|s| s.to_string());
        }
    }
    None
}

/// Read VS_FIXEDFILEINFO from a PE image's resource section in guest memory.
///
/// Reads only the header page + the `.rsrc` section (not the full image) to
/// extract file version and product version strings. Returns `None` if the
/// image has no resources, the resource section is paged out, or no
/// RT_VERSION resource is present.
pub fn read_pe_version_info<B: MemoryOps<PhysAddr>>(
    base: VirtAddr,
    memory: &memory::AddressSpace<'_, B>,
) -> Option<(String, String)> {
    use pelite::image::IMAGE_DIRECTORY_ENTRY_RESOURCE;

    let header_buf = read_pe_header_page(base, memory).ok()?;
    let view = PeView::from_bytes(&header_buf).ok()?;

    let rsrc_dir = view.data_directory().get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    let rsrc_rva = rsrc_dir.VirtualAddress;
    let rsrc_size = (rsrc_dir.Size as usize).min(256 * 1024);
    if rsrc_size < 16 {
        return None;
    }

    let mut rsrc_buf = vec![0u8; rsrc_size];
    memory
        .read_bytes(VirtAddr(base.0 + rsrc_rva as u64), &mut rsrc_buf)
        .ok()?;

    let data_entry_rva = find_rt_version_data_entry(&rsrc_buf, rsrc_rva)?;

    let ver_rva = read_u32_at(&rsrc_buf, data_entry_rva)?;
    let ver_size = read_u32_at(&rsrc_buf, data_entry_rva + 4)? as usize;
    if !(52..=32 * 1024).contains(&ver_size) {
        return None;
    }

    let ver_offset_in_rsrc = (ver_rva as usize).checked_sub(rsrc_rva as usize)?;
    let ver_data = rsrc_buf.get(ver_offset_in_rsrc..ver_offset_in_rsrc + ver_size)?;

    parse_vs_fixedfileinfo(ver_data)
}

const RT_VERSION: u32 = 16;
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF04BD;

/// Navigate the resource directory tree (3 levels) to find the
/// IMAGE_RESOURCE_DATA_ENTRY for the first RT_VERSION resource.
/// Returns the offset within `rsrc` of the data entry (which holds
/// the RVA and size of the VS_VERSION_INFO blob).
fn find_rt_version_data_entry(rsrc: &[u8], rsrc_rva: u32) -> Option<usize> {
    // Level 0: root directory — find type entry for RT_VERSION
    let type_entry = find_resource_id_entry(rsrc, 0, RT_VERSION)?;
    // Level 1: name directory — take first entry
    let name_entry = first_resource_entry(rsrc, type_entry)?;
    // Level 2: language directory — take first entry
    let lang_entry = first_resource_entry(rsrc, name_entry)?;

    // lang_entry should point to a data entry (bit 31 clear)
    if lang_entry & 0x8000_0000 != 0 {
        return None;
    }
    let data_entry_off = lang_entry as usize;
    if data_entry_off + 16 > rsrc.len() {
        return None;
    }

    // Validate: the RVA should fall within the resource section
    let rva = read_u32_at(rsrc, data_entry_off)?;
    if rva < rsrc_rva || (rva as usize - rsrc_rva as usize) >= rsrc.len() {
        return None;
    }
    Some(data_entry_off)
}

/// Scan an IMAGE_RESOURCE_DIRECTORY at `dir_off` for an entry with the
/// given resource ID. Returns the OffsetToData/OffsetToDirectory value
/// from the matching entry (with the high bit preserved).
fn find_resource_id_entry(rsrc: &[u8], dir_off: usize, target_id: u32) -> Option<u32> {
    if dir_off + 16 > rsrc.len() {
        return None;
    }
    let num_named = read_u16_at(rsrc, dir_off + 12)? as usize;
    let num_id = read_u16_at(rsrc, dir_off + 14)? as usize;
    let entries_start = dir_off + 16;
    for i in num_named..(num_named + num_id) {
        let entry_off = entries_start + i * 8;
        let id = read_u32_at(rsrc, entry_off)?;
        if id == target_id {
            return read_u32_at(rsrc, entry_off + 4);
        }
    }
    None
}

/// Return the OffsetToData of the first entry in the directory at the
/// offset encoded in `parent_entry` (which must have bit 31 set for a
/// subdirectory).
fn first_resource_entry(rsrc: &[u8], parent_entry: u32) -> Option<u32> {
    if parent_entry & 0x8000_0000 == 0 {
        return None;
    }
    let dir_off = (parent_entry & 0x7FFF_FFFF) as usize;
    if dir_off + 16 > rsrc.len() {
        return None;
    }
    let num_named = read_u16_at(rsrc, dir_off + 12)? as usize;
    let num_id = read_u16_at(rsrc, dir_off + 14)? as usize;
    if num_named + num_id == 0 {
        return None;
    }
    let first_entry_off = dir_off + 16;
    read_u32_at(rsrc, first_entry_off + 4)
}

fn parse_vs_fixedfileinfo(data: &[u8]) -> Option<(String, String)> {
    // Search for VS_FIXEDFILEINFO signature
    let sig_bytes = VS_FIXEDFILEINFO_SIGNATURE.to_le_bytes();
    let pos = data.windows(4).position(|w| w == sig_bytes)?;
    if pos + 52 > data.len() {
        return None;
    }
    let info = &data[pos..];

    // dwFileVersionMS: HIWORD = Major, LOWORD = Minor
    // dwFileVersionLS: HIWORD = Build, LOWORD = Revision
    let file_minor = u16::from_le_bytes([info[8], info[9]]);
    let file_major = u16::from_le_bytes([info[10], info[11]]);
    let file_revision = u16::from_le_bytes([info[12], info[13]]);
    let file_build = u16::from_le_bytes([info[14], info[15]]);

    let prod_minor = u16::from_le_bytes([info[16], info[17]]);
    let prod_major = u16::from_le_bytes([info[18], info[19]]);
    let prod_revision = u16::from_le_bytes([info[20], info[21]]);
    let prod_build = u16::from_le_bytes([info[22], info[23]]);

    let file_ver = format!(
        "{}.{}.{}.{}",
        file_major, file_minor, file_build, file_revision
    );
    let prod_ver = format!(
        "{}.{}.{}.{}",
        prod_major, prod_minor, prod_build, prod_revision
    );
    Some((file_ver, prod_ver))
}

fn read_u16_at(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn populate_module_versions<B: MemoryOps<PhysAddr>>(
    modules: &mut [ModuleInfo],
    memory: &memory::AddressSpace<'_, B>,
) {
    for module in modules.iter_mut() {
        if let Some((file_ver, prod_ver)) = read_pe_version_info(module.base_address, memory) {
            module.file_version = Some(file_ver);
            module.product_version = Some(prod_ver);
        }
    }
}

/// Build a complete (hole-free) `PeImage` from an on-disk PE file by mapping its
/// raw sections to their RVAs: the same layout `read_pe_image` produces from
/// guest memory, but sourced from the full file. Used to recover read-only data
/// (e.g. unwind tables) when the in-memory image has paged-out holes.
pub fn read_pe_image_from_file(path: &Path) -> Result<PeImage> {
    let data = std::fs::read(path)?;
    let file = PeFile::from_bytes(&data)?;
    let (total_size, size_of_headers) = match file.optional_header() {
        Wrap::T32(header) => (header.SizeOfImage as usize, header.SizeOfHeaders as usize),
        Wrap::T64(header) => (header.SizeOfImage as usize, header.SizeOfHeaders as usize),
    };
    let mut image_buffer = vec![0u8; total_size];

    let headers_size = size_of_headers.min(total_size).min(data.len());
    image_buffer[..headers_size].copy_from_slice(&data[..headers_size]);

    for section in file.section_headers() {
        let v_addr = section.VirtualAddress as usize;
        let raw_ptr = section.PointerToRawData as usize;
        let raw_size = section.SizeOfRawData as usize;
        if raw_size == 0 || v_addr + raw_size > total_size || raw_ptr + raw_size > data.len() {
            continue;
        }
        image_buffer[v_addr..v_addr + raw_size].copy_from_slice(&data[raw_ptr..raw_ptr + raw_size]);
    }

    Ok(PeImage::complete(image_buffer))
}

pub struct SymbolRef<'a> {
    obj: &'a Image,
    rva: u32,
}

impl SymbolRef<'_> {
    pub fn address(&self) -> VirtAddr {
        self.obj.address_of(self.rva)
    }

    pub fn read<T>(&self) -> Result<T>
    where
        T: IntoBytes + FromBytes + Copy,
    {
        self.obj.memory().read(self.address())
    }
}

/// A PE image mapped into guest memory: ntoskrnl, a driver, or a user-mode
/// EXE/DLL. It carries the address space it is mapped in (`dtb`) and the
/// handles needed to read it and resolve its symbols and types, so navigation
/// methods don't take them as arguments. The handles are shared (`Arc`), not
/// borrowed; an `Image` can't borrow its `Target` siblings, but it can own
/// a refcounted handle to them.
pub struct Image {
    pub base_address: VirtAddr,
    dtb: Dtb,
    arch: Arch,
    /// AArch64 TTBR1 (kernel-space root). Equal to `dtb` for the kernel object
    /// and AMD64; process siblings keep the kernel root for kernel-VA reads.
    kernel_dtb: Dtb,
    /// Header page read at symbol load; nothing from the sections.
    headers: Option<Box<[u8]>>,
    /// Demand-read image shared across stack traces, so each block is
    /// fetched once per session.
    image: Mutex<Option<Arc<PeImage>>>,
    pub guid: Option<u128>,
    phys: Arc<PhysMem>,
    symbols: Arc<SymbolStore>,
}

impl Image {
    pub fn new(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        dtb: Dtb,
        base_address: VirtAddr,
        arch: Arch,
    ) -> Self {
        Self {
            base_address,
            dtb,
            arch,
            kernel_dtb: dtb,
            headers: None,
            image: Mutex::new(None),
            guid: None,
            phys,
            symbols,
        }
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn load_symbols(mut self) -> Result<Self> {
        let symbols = Arc::clone(&self.symbols);
        self.guid = symbols.load_from_binary(&mut self, "ntoskrnl.exe")?;
        Ok(self)
    }

    /// Fallback symbol loader for triage dumps where the PE header page isn't
    /// in the dump.  Uses the module's TimeDateStamp + SizeOfImage from the
    /// triage driver list to download the PE from Microsoft's symbol server,
    /// extract the PDB GUID, and load the PDB.
    pub fn load_symbols_from_module_info(
        mut self,
        name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<Self> {
        let symbols = Arc::clone(&self.symbols);
        self.guid = symbols.load_from_module_info(
            name,
            self.base_address,
            self.dtb,
            time_date_stamp,
            size_of_image,
        )?;
        Ok(self)
    }

    pub fn dtb(&self) -> Dtb {
        self.dtb
    }

    /// Mark this object's module as the kernel in the shared symbol store:
    /// type/enum layout lookups prefer it, and its address space is visible
    /// from every process. Call after [`load_symbols`](Self::load_symbols) so
    /// `guid` is populated.
    pub fn register_as_kernel(&self) {
        self.symbols.set_kernel(self.guid, self.dtb);
    }

    /// `SizeOfImage` of the module (0 until [`view`](Self::view) has run).
    pub fn binary_size(&self) -> usize {
        self.headers
            .as_deref()
            .and_then(|headers| PeView::from_bytes(headers).ok())
            .map_or(0, |view| size_of_image(&view) as usize)
    }

    pub fn address_of(&self, rva: impl Into<u64>) -> VirtAddr {
        self.base_address + rva.into()
    }

    pub fn memory(&self) -> AddressSpace<'_, Arc<PhysMem>> {
        self.memory_in(self.dtb)
    }

    /// Like [`memory`](Self::memory), but rooted at `dtb`: another process's
    /// space, keeping this object's architecture and kernel root.
    pub fn memory_in(&self, dtb: Dtb) -> AddressSpace<'_, Arc<PhysMem>> {
        AddressSpace::for_arch(&self.phys, dtb, self.kernel_dtb, self.arch)
    }

    pub fn symbol<S>(&self, name: S) -> Result<SymbolRef<'_>>
    where
        S: Into<String>,
    {
        let name = name.into();

        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let rva = self
            .symbols
            .symbol_rva(guid, &name)?
            .ok_or(Error::SymbolNotFound(name))?;
        Ok(SymbolRef { obj: self, rva })
    }

    pub fn closest_symbol(&self, address: VirtAddr) -> Result<(String, u32)> {
        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let result = self
            .symbols
            .closest_symbol(guid, self.base_address, address)
            .ok_or(Error::UnknownAddress(address))?;
        Ok(result)
    }

    /// The module's headers, read once from guest memory. Directories past
    /// the headers are not in the view; see [`image`](Self::image) for those.
    pub fn view(&mut self) -> Option<PeView<'_>> {
        if self.headers.is_none() {
            let headers = read_pe_header_page(self.base_address, &self.memory()).ok()?;
            self.headers = Some(Box::new(headers));
        }

        PeView::from_bytes(self.headers.as_deref()?).ok()
    }

    /// The in-memory image (see [`read_pe_image`]), opened on first use and
    /// shared afterwards. `None` when the headers are unreadable; that is
    /// retried next time rather than cached.
    pub fn image(&self) -> Option<Arc<PeImage>> {
        let mut cached = self.image.lock().unwrap_or_else(PoisonError::into_inner);
        if cached.is_none() {
            let image = self.read_image().ok()?;
            *cached = Some(Arc::new(image));
        }
        cached.clone()
    }

    /// Read the mapped PE image in this object's address space.
    pub fn read_image(&self) -> Result<PeImage> {
        let (phys, dtb, kernel_dtb, arch) =
            (Arc::clone(&self.phys), self.dtb, self.kernel_dtb, self.arch);
        read_pe_image(self.base_address, move |address, buf| {
            AddressSpace::for_arch(&phys, dtb, kernel_dtb, arch).read_bytes(address, buf)
        })
    }

    /// Resolve this object's struct/type namespace, read in its own address
    /// space. Use [`types_in`](Self::types_in) to read the same types from a
    /// different `dtb` (e.g. ntoskrnl's kernel types against a process's space).
    pub fn types(&self) -> Types<'_> {
        self.types_in(self.dtb)
    }

    /// Like [`types`](Self::types), but reads against `dtb` instead of this
    /// object's own, for kernel types navigated through a process's space.
    pub fn types_in(&self, dtb: Dtb) -> Types<'_> {
        Types {
            symbols: &self.symbols,
            guid: self.guid,
            phys: &self.phys,
            arch: self.arch,
            kernel_dtb: self.kernel_dtb,
            dtb,
        }
    }
}

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
    /// The namespace of module `guid` (see [`Image::types_in`]) without an
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
/// [`SymbolRef`] is to symbols: `follow`/`read_field`/`list` chain off it, and
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

/// Read a loader-table record (`_LDR_DATA_TABLE_ENTRY` / `_KLDR_DATA_TABLE_ENTRY`)
/// into a `ModuleInfo`, or `None` when it has no base address (skip it). Shared
/// by the process- and kernel-module walks, which differ only in their list.
fn module_info_from_record(record: &StructRef<'_>) -> Result<Option<ModuleInfo>> {
    let dll_base = record.read_pointer("DllBase")?;
    if dll_base.is_zero() {
        return Ok(None);
    }
    let size_of_image: u32 = record.read_field("SizeOfImage")?;
    let name = record
        .unicode_string("BaseDllName")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<unknown>".to_string());
    let mut info = ModuleInfo::new(name, dll_base, size_of_image);
    info.path = record
        .unicode_string("FullDllName")
        .ok()
        .filter(|path| !path.is_empty());
    if let Ok(entry_point) = record.read_pointer("EntryPoint")
        && !entry_point.is_zero()
    {
        info.entry_point = Some(entry_point);
    }
    if let Ok(tds) = record.read_field::<u32>("TimeDateStamp") {
        info = info.with_time_date_stamp(tds);
    }
    if let Ok(cs) = record.read_field::<u32>("CheckSum") {
        info = info.with_checksum(cs);
    }
    Ok(Some(info))
}

fn read_loader_pointer(
    memory: &impl MemoryOps<VirtAddr>,
    address: VirtAddr,
    pointer_size: usize,
) -> Result<VirtAddr> {
    if pointer_size == 4 {
        memory
            .read::<u32>(address)
            .map(|pointer| VirtAddr(u64::from(pointer)))
    } else {
        memory.read::<u64>(address).map(VirtAddr)
    }
}

fn read_unicode32(memory: &impl MemoryOps<VirtAddr>, length: usize, buffer: u32) -> Option<String> {
    if length == 0 || buffer == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length];
    memory
        .read_bytes(VirtAddr(u64::from(buffer)), &mut bytes)
        .ok()?;
    let utf16: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    Some(String::from_utf16_lossy(&utf16))
}

pub struct Guest {
    pub ntoskrnl: Image,
    memo: Mutex<HaltMemo>,
}

/// The `_EPROCESS` fields process enumeration needs, fetched with one read
/// covering their span instead of one request per field over the transport.
struct EprocessSpan {
    start: u64,
    bytes: Vec<u8>,
    unique_process_id_offset: u64,
    dir_table_base_offset: u64,
    active_process_links_offset: u64,
    image_file_name_offset: u64,
    /// `WoW64Process`, absent from an x86 kernel's `_EPROCESS`.
    wow64_process_offset: Option<u64>,
}

impl EprocessSpan {
    fn new(guest: &Guest) -> Result<Self> {
        let eprocess = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let kprocess = guest.ntoskrnl.types().layout("_KPROCESS")?;
        let unique_process_id_offset = eprocess.field_offset("UniqueProcessId")?;
        let dir_table_base_offset =
            eprocess.field_offset("Pcb")? + kprocess.field_offset("DirectoryTableBase")?;
        let active_process_links_offset = eprocess.field_offset("ActiveProcessLinks")?;
        let image_file_name_offset = eprocess.field_offset("ImageFileName")?;
        let wow64_process_offset = eprocess
            .field_offset("WoW64Process")
            .or_else(|_| eprocess.field_offset("Wow64Process"))
            .ok();
        let start = unique_process_id_offset
            .min(dir_table_base_offset)
            .min(active_process_links_offset)
            .min(image_file_name_offset)
            .min(wow64_process_offset.unwrap_or(u64::MAX));
        let end = (unique_process_id_offset + 8)
            .max(dir_table_base_offset + 8)
            .max(active_process_links_offset + 8)
            .max(image_file_name_offset + IMAGE_FILE_NAME_LEN as u64)
            .max(wow64_process_offset.map_or(0, |offset| offset + 8));
        Ok(Self {
            start,
            bytes: vec![0u8; (end - start) as usize],
            unique_process_id_offset,
            dir_table_base_offset,
            active_process_links_offset,
            image_file_name_offset,
            wow64_process_offset,
        })
    }

    fn read(&mut self, memory: &impl MemoryOps<VirtAddr>, eprocess: VirtAddr) -> Result<()> {
        memory.read_bytes(eprocess + self.start, &mut self.bytes)
    }

    fn u64_at(&self, offset: u64) -> u64 {
        let start = (offset - self.start) as usize;
        u64::from_le_bytes(self.bytes[start..start + 8].try_into().unwrap())
    }

    fn pid(&self) -> u64 {
        self.u64_at(self.unique_process_id_offset)
    }

    fn dtb(&self) -> Dtb {
        self.u64_at(self.dir_table_base_offset) & !0xfff
    }

    fn active_process_links_flink(&self) -> VirtAddr {
        VirtAddr(self.u64_at(self.active_process_links_offset))
    }

    fn image_file_name(&self) -> &[u8] {
        let start = (self.image_file_name_offset - self.start) as usize;
        &self.bytes[start..start + IMAGE_FILE_NAME_LEN]
    }

    /// `_EPROCESS.WoW64Process`: null for a native process.
    fn wow64_process(&self) -> Option<VirtAddr> {
        self.wow64_process_offset
            .map(|offset| VirtAddr(self.u64_at(offset)))
            .filter(|pointer| !pointer.is_zero())
    }
}

/// Guest-derived lists memoized for one halt epoch (see
/// [`PhysMem::halt_epoch`]). A halted guest cannot relink these lists, so the
/// first walk per halt serves every later caller: the break context, the
/// stop-time symbol refresh, completions, and listing commands would otherwise
/// each re-walk the same kernel lists over the transport. Failed walks are not
/// remembered.
#[derive(Default)]
struct HaltMemo {
    epoch: Option<u64>,
    processes: Option<Vec<ProcessInfo>>,
    kernel_modules: Option<Vec<ModuleInfo>>,
    drivers: Option<Vec<DriverObjectInfo>>,
    /// Loader lists by `_EPROCESS`; every thread of a process walked in one
    /// halt shares them.
    process_modules: HashMap<VirtAddr, Option<ProcessModulesDetail>>,
}

fn is_valid_kernel_dtb_amd64(phys: &PhysMem, dtb: Dtb) -> Result<bool> {
    let Ok(kernel_pml4) = phys.read::<[PageTableEntry; 256]>(dtb + 8 * 256) else {
        // Candidate sits outside mapped guest RAM (below the aarch64 RAM
        // base, in an MMIO hole, or past the end): not a kernel root.
        return Ok(false);
    };

    if kernel_pml4
        .into_iter()
        .filter(|e| e.page_frame() == dtb)
        .count()
        != 1
    {
        return Ok(false);
    }

    // Check if use KUSER_SHARED_DATA is mapped
    const KUSER_SHARED_DATA_VA: VirtAddr = VirtAddr::from_u64(0xfffff78000000000);

    let addr_space = AddressSpace::new(phys, dtb);

    if let Some(xlat) = addr_space.virt_to_phys(KUSER_SHARED_DATA_VA)?
        && !xlat.user
        && xlat.nx
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn find_kernel_dtb_amd64(phys: &PhysMem) -> Result<Option<Dtb>> {
    let base = phys.ram_base();
    for dtb in (base + 0x1000..base + 0x1000000).step_by(PAGE_SIZE) {
        if is_valid_kernel_dtb_amd64(phys, dtb)? {
            return Ok(Some(dtb));
        }
    }

    Ok(None)
}

/// AArch64 kernel (TTBR1) root candidate: KUSER_SHARED_DATA must translate to
/// the *actual* shared-data page. Windows maps KUSER user-accessible (AP[2]=1)
/// and with UXN set, so attribute checks can't discriminate a real root from a
/// random table that happens to translate something; the page content can —
/// KUSER carries ImageNumberLow/High 0xaa64 at offset 0x2C and the
/// "C:\Windows" system root at 0x30 (this ARM64 layout differs from x64's
/// 0x20/0x38, so those offsets are checked exactly as observed).
fn is_valid_kernel_dtb_arm64(phys: &PhysMem, dtb: Dtb) -> Result<bool> {
    const KUSER_SHARED_DATA_VA: VirtAddr = VirtAddr::from_u64(0xfffff78000000000);

    let addr_space = AddressSpace::new_arm64(phys, dtb, dtb);
    let Some(xlat) = addr_space.virt_to_phys(KUSER_SHARED_DATA_VA)? else {
        return Ok(false);
    };
    let mut buf = [0u8; 0x40];
    if phys.read_bytes(xlat.address, &mut buf).is_err() {
        return Ok(false);
    }
    Ok(buf[0x2C..0x30] == [0x64, 0xaa, 0x64, 0xaa]
        && buf[0x30] == b'C'
        && buf[0x32] == b':'
        && buf[0x34] == b'\\')
}

/// Read the PE machine type of the kernel image found through `dtb` with the
/// arch's walker, or `None` when no valid PE header is there. This is the
/// definitive architecture check: a kernel image's machine must be 0x8664
/// (AMD64) or 0xaa64 (ARM64), which an accidental page-table false positive
/// cannot satisfy.
fn kernel_machine_at(dtb: Dtb, phys: &PhysMem, arch: Arch) -> Result<Option<u16>> {
    let base = match arch {
        Arch::Amd64 => find_ntoskrnl_va(dtb, phys)?,
        Arch::Arm64 => find_ntoskrnl_va_arm64(dtb, phys)?,
    };
    let Some(base) = base else {
        return Ok(None);
    };
    let space = match arch {
        Arch::Amd64 => AddressSpace::new(phys, dtb),
        Arch::Arm64 => AddressSpace::new_arm64(phys, dtb, dtb),
    };
    // The base must read as a real DOS header ("MZ" + 0x90) through this
    // walker — a page-table false positive cannot satisfy this plus a valid
    // PE signature and matching machine type.
    let mut dos = [0u8; 4];
    if space.read_bytes(base, &mut dos).is_err() || dos != [0x4d, 0x5a, 0x90, 0x00] {
        return Ok(None);
    }
    let lfanew: u32 = match space.read(base + 0x3Cu64) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if lfanew == 0 || lfanew > 0x1000 {
        return Ok(None);
    }
    let mut sig = [0u8; 6];
    if space.read_bytes(base + lfanew as u64, &mut sig).is_err() || &sig[..4] != b"PE\0\0" {
        return Ok(None);
    }
    Ok(Some(u16::from_le_bytes([sig[4], sig[5]])))
}

/// Discover the kernel page-table root and guest architecture. The AMD64
/// descriptor format is tried first (the historical default), but a candidate
/// only counts when the kernel image found through it is genuinely an AMD64
/// PE: an AArch64 guest's TTBR1 tables can false-positive the x64 descriptor
/// checks (Windows maps its own page tables), and the weak MZ+POOLCODE page
/// heuristic can match a data page. The PE machine type is the tie-breaker.
pub fn find_kernel(phys: &PhysMem) -> Result<Option<(Dtb, Arch)>> {
    if let Some(dtb) = find_kernel_dtb_amd64(phys)?
        && matches!(kernel_machine_at(dtb, phys, Arch::Amd64)?, Some(0x8664))
    {
        return Ok(Some((dtb, Arch::Amd64)));
    }
    for dtb in find_kernel_dtb_arm64_candidates(phys)? {
        if matches!(kernel_machine_at(dtb, phys, Arch::Arm64)?, Some(0xaa64)) {
            return Ok(Some((dtb, Arch::Arm64)));
        }
    }
    Ok(None)
}

/// Scan guest RAM for AArch64 TTBR1 roots: page-aligned pages whose L0 entry
/// for KUSER_SHARED_DATA is a table descriptor pointing inside RAM. The full
/// translation must reach a page with the ARM64 KUSER signature; the caller
/// then validates the kernel image's PE machine type.
fn find_kernel_dtb_arm64_candidates(phys: &PhysMem) -> Result<Vec<Dtb>> {
    const KUSER_L0_INDEX: u64 = 495;
    const MAX_CANDIDATES: usize = 32;
    let base = phys.ram_base();
    let ram_end = base.saturating_add(phys.ram_size());
    let mut out = Vec::new();
    for dtb in (base.saturating_add(0x1000)..ram_end).step_by(PAGE_SIZE) {
        let Ok(entry) = phys.read::<PageTableEntry>(dtb + 8 * KUSER_L0_INDEX) else {
            continue;
        };
        // Table descriptor (bits[1:0] = 0b11) whose table lies in RAM.
        if entry.0 & 0b11 != 0b11 {
            continue;
        }
        let frame = entry.arm64_page_frame();
        if frame < base || frame >= ram_end {
            continue;
        }
        if is_valid_kernel_dtb_arm64(phys, dtb)? {
            out.push(dtb);
            if out.len() >= MAX_CANDIDATES {
                break;
            }
        }
    }
    Ok(out)
}

fn is_ntoskrnl_header(header: &[u8]) -> bool {
    header.len() >= 4
        && header[..4] == [0x4d, 0x5a, 0x90, 0x00]
        && header.as_chunks::<8>().0.iter().any(|c| c == b"POOLCODE")
}

/// Whether the kernel-only, no-execute page at `frame` (mapped by `entry`)
/// starts with the ntoskrnl image header.
fn is_ntoskrnl_page(
    phys: &impl MemoryOps<PhysAddr>,
    entry: PageTableEntry,
    frame: PhysAddr,
) -> Result<bool> {
    if entry.is_user() || !entry.is_nx() {
        return Ok(false);
    }

    let Ok(header) = phys.read::<[u8; 0x1000]>(frame) else {
        return Ok(false);
    };
    Ok(is_ntoskrnl_header(&header))
}

fn find_ntoskrnl_va(kernel_dtb: Dtb, phys: &impl MemoryOps<PhysAddr>) -> Result<Option<VirtAddr>> {
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xfffff80800000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let Ok(kernel_pml4) = phys.read::<[PageTableEntry; 256]>(kernel_dtb + 8 * 256) else {
        return Ok(None);
    };
    for (rel_pml4_index, pml4e) in kernel_pml4
        .into_iter()
        .enumerate()
        .skip(KERNEL_VA_MIN.pml4_index() - 256)
        .take(pml4e_count)
    {
        let pml4_index = 256 + rel_pml4_index;

        if !pml4e.is_present() {
            continue;
        }
        let Ok(pdpt) = phys.read::<[PageTableEntry; 512]>(pml4e.page_frame()) else {
            continue;
        };

        // The scan ends at KERNEL_VA_MAX (inclusive): each level is clamped
        // only on the path that leads to it.
        let on_last_pml4 = pml4_index == KERNEL_VA_MAX.pml4_index();
        let pdpte_count = if on_last_pml4 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (pdpt_index, pdpte) in pdpt.into_iter().take(pdpte_count).enumerate() {
            if !pdpte.is_present() {
                continue;
            }

            if pdpte.is_large_page() {
                if let Ok(true) = is_ntoskrnl_page(phys, pdpte, pdpte.huge_page_frame()) {
                    return Ok(Some(VirtAddr::construct(pml4_index, pdpt_index, 0, 0)));
                }

                continue;
            }

            let Ok(pd) = phys.read::<[PageTableEntry; 512]>(pdpte.page_frame()) else {
                continue;
            };

            let on_last_pdpt = on_last_pml4 && pdpt_index == KERNEL_VA_MAX.pdpt_index();
            let pde_count = if on_last_pdpt {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (pd_index, pde) in pd.into_iter().take(pde_count).enumerate() {
                if !pde.is_present() {
                    continue;
                }

                if pde.is_large_page() {
                    if let Ok(true) = is_ntoskrnl_page(phys, pde, pde.large_page_frame()) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, pdpt_index, pd_index, 0,
                        )));
                    }

                    continue;
                }

                let Ok(pt) = phys.read::<[PageTableEntry; 512]>(pde.page_frame()) else {
                    continue;
                };

                let pte_count = if on_last_pdpt && pd_index == KERNEL_VA_MAX.pd_index() {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (pt_index, pte) in pt.into_iter().take(pte_count).enumerate() {
                    if !pte.is_present() {
                        continue;
                    }

                    if let Ok(true) = is_ntoskrnl_page(phys, pte, pte.page_frame()) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, pdpt_index, pd_index, pt_index,
                        )));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn is_ntoskrnl_pte_arm64(phys: &PhysMem, pte: PageTableEntry) -> Result<bool> {
    // Kernel code pages: AP[2]=0 (not user), PXN=0 (executable from EL1).
    // (UXN is always set on Windows kernel pages, so it cannot identify code.)
    if pte.arm64_is_user() || !pte.arm64_is_pxn() {
        return Ok(false);
    }

    is_ntoskrnl_header_at(phys, pte.arm64_page_frame())
}

/// Whether the physical page at `frame` holds the ntoskrnl PE header
/// (MZ + POOLCODE marker). Tolerant of unreadable/unmapped frames.
fn is_ntoskrnl_header_at(phys: &PhysMem, frame: u64) -> Result<bool> {
    let Ok(header) = phys.read::<[u8; 0x1000]>(frame) else {
        return Ok(false);
    };
    Ok(is_ntoskrnl_header(&header))
}

/// Same bounded kernel-VA scan as [`find_ntoskrnl_va`] but interpreting
/// AArch64 descriptors (TTBR1 root, 4 KiB granule). The VA index math is
/// identical to x64's four 9-bit levels.
fn find_ntoskrnl_va_arm64(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    // Cover the Windows ARM64 kernel VA range. Unlike the AMD64 scan's narrow
    // low-kernel slot, this includes every populated L0 slot from 496 through
    // the inclusive upper bound.
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xffffff8000000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let Ok(kernel_table) = phys.read::<[PageTableEntry; 256]>(kernel_dtb + 8 * 256) else {
        return Ok(None);
    };
    for (rel_index, l0) in kernel_table
        .into_iter()
        .enumerate()
        .skip(KERNEL_VA_MIN.pml4_index() - 256)
        .take(pml4e_count)
    {
        let pml4_index = 256 + rel_index;

        if !l0.arm64_is_valid() || l0.arm64_is_block() {
            continue;
        }
        let Ok(l1_table) = phys.read::<[PageTableEntry; 512]>(l0.arm64_page_frame()) else {
            continue;
        };

        let on_upper_l0 = pml4_index == KERNEL_VA_MAX.pml4_index();
        let l1_count = if on_upper_l0 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (l1_index, l1) in l1_table.into_iter().take(l1_count).enumerate() {
            if !l1.arm64_is_valid() {
                continue;
            }

            if l1.arm64_is_block() {
                // A 1 GiB block is unlikely for ntoskrnl. Probe each 2 MiB
                // boundary and reconstruct the matching VA at the L2 index.
                let block = l1.arm64_huge_block_frame();
                for l2_index in 0..512u64 {
                    if is_ntoskrnl_header_at(phys, block + l2_index * (2 << 20))? {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index,
                            l1_index,
                            l2_index as usize,
                            0,
                        )));
                    }
                }
                continue;
            }

            let Ok(l2_table) = phys.read::<[PageTableEntry; 512]>(l1.arm64_page_frame()) else {
                continue;
            };

            let on_upper_l1 = on_upper_l0 && l1_index == KERNEL_VA_MAX.pdpt_index();
            let l2_count = if on_upper_l1 {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (l2_index, l2) in l2_table.into_iter().take(l2_count).enumerate() {
                if !l2.arm64_is_valid() {
                    continue;
                }

                if l2.arm64_is_block() {
                    // Probe every 4 KiB page in the 2 MiB block; the PE image
                    // need not begin at the block's first page.
                    let block = l2.arm64_large_block_frame();
                    for pt_index in 0..512u64 {
                        if is_ntoskrnl_header_at(phys, block + pt_index * 0x1000)? {
                            return Ok(Some(VirtAddr::construct(
                                pml4_index,
                                l1_index,
                                l2_index,
                                pt_index as usize,
                            )));
                        }
                    }
                    continue;
                }

                let Ok(l3_table) = phys.read::<[PageTableEntry; 512]>(l2.arm64_page_frame()) else {
                    continue;
                };

                let on_upper_l2 = on_upper_l1 && l2_index == KERNEL_VA_MAX.pd_index();
                let l3_count = if on_upper_l2 {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (l3_index, l3) in l3_table.into_iter().take(l3_count).enumerate() {
                    if l3.0 & 0b11 != 0b11 {
                        continue;
                    }

                    if let Ok(true) = is_ntoskrnl_pte_arm64(phys, l3) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, l1_index, l2_index, l3_index,
                        )));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Scan captured virtual memory regions for the ntoskrnl PE header.
///
/// Triage dumps have no page tables, so we can't walk the PML4. Instead we
/// probe the identity-mapped virtual memory for the MZ header + POOLCODE
/// marker, the same heuristic `is_ntoskrnl_pte` uses but at the virtual
/// layer.
fn find_ntoskrnl_va_triage(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    let space = AddressSpace::new(phys, kernel_dtb);

    // No PDB yet, so PsLoadedModuleList can't be walked; probe the data
    // blocks for kernel-space PE headers instead.
    if let Some(dmp_info) = phys.dmp_info() {
        // Check triage driver base addresses first — ntoskrnl is typically
        // the first entry and this avoids scanning up to 4096 pages.
        let mut header = vec![0u8; 0x1000];
        for driver in &dmp_info.triage_drivers {
            let candidate = VirtAddr(driver.base);
            if space.read_bytes(candidate, &mut header).is_err() {
                continue;
            }
            if is_ntoskrnl_header(&header) {
                return Ok(Some(candidate));
            }
        }

        // Fallback: scan backwards from PsLoadedModuleList.
        let ps_loaded = dmp_info.ps_loaded_module_list;
        if ps_loaded >= 0xfffff80000000000 {
            let page_base = ps_loaded & !0xFFF;
            for offset in (0..0x100_0000u64).step_by(0x1000) {
                let candidate = page_base - offset;
                if space.read_bytes(VirtAddr(candidate), &mut header).is_err() {
                    continue;
                }
                if is_ntoskrnl_header(&header) {
                    return Ok(Some(VirtAddr(candidate)));
                }
            }
        }
    }

    Ok(None)
}

fn find_ntoskrnl(phys: Arc<PhysMem>, symbols: Arc<SymbolStore>) -> Result<Option<Image>> {
    let Some((kernel_dtb, arch)) = find_kernel(&phys)? else {
        return Ok(None);
    };

    let ntoskrnl_va = match arch {
        Arch::Amd64 => find_ntoskrnl_va(kernel_dtb, &phys)?,
        Arch::Arm64 => find_ntoskrnl_va_arm64(kernel_dtb, &phys)?,
    };
    let Some(ntoskrnl_va) = ntoskrnl_va else {
        return Ok(None);
    };

    Ok(Some(Image::new(
        phys,
        symbols,
        kernel_dtb,
        ntoskrnl_va,
        arch,
    )))
}

impl Guest {
    pub fn from_kernel(ntoskrnl: Image) -> Self {
        Self {
            ntoskrnl,
            memo: Mutex::new(HaltMemo::default()),
        }
    }

    fn memo(&self) -> MutexGuard<'_, HaltMemo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serve `slot` from the current halt's memo, walking with `walk` on a
    /// miss. Memory without a halt signal is never memoized.
    fn memoized<T: Clone>(
        &self,
        slot: impl Fn(&mut HaltMemo) -> &mut Option<T>,
        walk: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let Some(epoch) = self.ntoskrnl.phys.halt_epoch() else {
            return walk();
        };
        {
            let mut memo = self.memo();
            if memo.epoch != Some(epoch) {
                *memo = HaltMemo {
                    epoch: Some(epoch),
                    ..HaltMemo::default()
                };
            }
            if let Some(list) = slot(&mut memo) {
                return Ok(list.clone());
            }
        }
        let list = walk()?;
        let mut memo = self.memo();
        if memo.epoch == Some(epoch) {
            *slot(&mut memo) = Some(list.clone());
        }
        Ok(list)
    }

    pub fn memoized_drivers(
        &self,
        walk: impl FnOnce() -> Result<Vec<DriverObjectInfo>>,
    ) -> Result<Vec<DriverObjectInfo>> {
        self.memoized(|memo| &mut memo.drivers, walk)
    }

    fn apply_module_symbol_status(
        symbols: &SymbolStore,
        report: &mut ModuleSymbolLoadReport,
        dtb: Dtb,
        module: &ModuleInfo,
        status: ModuleSymbolStatus,
    ) {
        symbols.set_module_symbol_status(dtb, module.base_address, status.clone());
        report.record_status(&status);
    }

    pub fn new_with_kernel_base_hint(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        kernel_base_hint: Option<VirtAddr>,
    ) -> Result<Self> {
        if let Some(base) = kernel_base_hint {
            let (dtb, arch) = find_kernel(&phys)?.ok_or(Error::NtoskrnlNotFound)?;
            return Self::at(phys, symbols, KernelLocation { dtb, base, arch });
        }
        Self::with_kernel(find_ntoskrnl(phys, symbols)?.ok_or(Error::NtoskrnlNotFound)?)
    }

    /// The guest whose kernel is at `location`, with no memory scan.
    pub fn at(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        location: KernelLocation,
    ) -> Result<Self> {
        Self::with_kernel(Image::new(
            phys,
            symbols,
            location.dtb,
            location.base,
            location.arch,
        ))
    }

    fn with_kernel(ntoskrnl: Image) -> Result<Self> {
        let ntoskrnl = ntoskrnl.load_symbols()?;
        // Type/enum layout lookups prefer the kernel's definitions over
        // same-named user-mode types once attached to a process; tell the
        // symbol store which guid is the kernel's.
        ntoskrnl.register_as_kernel();
        Ok(Self::from_kernel(ntoskrnl))
    }

    pub fn new(phys: Arc<PhysMem>, symbols: Arc<SymbolStore>) -> Result<Self> {
        Self::new_with_kernel_base_hint(phys, symbols, None)
    }

    pub fn new_with_dtb(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        kernel_dtb: Dtb,
    ) -> Result<Self> {
        let is_triage = kernel_dtb == DTB_IDENTITY;

        // Dumps carry the machine type; live sessions reach this only from
        // discovery, which already resolved the arch.
        let arch = phys
            .dmp_info()
            .and_then(DmpInfo::arch)
            .unwrap_or(Arch::Amd64);

        let ntoskrnl_va = if is_triage {
            find_ntoskrnl_va_triage(kernel_dtb, &phys)?
        } else {
            match arch {
                Arch::Amd64 => find_ntoskrnl_va(kernel_dtb, &phys)?,
                Arch::Arm64 => find_ntoskrnl_va_arm64(kernel_dtb, &phys)?,
            }
        };

        // For triage dumps, fall back to kern_base from KDDEBUGGER_DATA64
        // when the PE header page isn't captured in the dump.
        let ntoskrnl_va = match ntoskrnl_va {
            Some(va) => va,
            None if is_triage => phys
                .dmp_info()
                .and_then(|i| i.kern_base)
                .map(VirtAddr)
                .ok_or(Error::NtoskrnlNotFound)?,
            None => return Err(Error::NtoskrnlNotFound),
        };

        let obj = Image::new(
            Arc::clone(&phys),
            Arc::clone(&symbols),
            kernel_dtb,
            ntoskrnl_va,
            arch,
        );

        // Try normal symbol loading first; for triage dumps where the PE
        // header isn't in memory, fall back to downloading by image metadata.
        let ntoskrnl = match obj.load_symbols() {
            Ok(loaded) => loaded,
            Err(error) if is_triage => {
                // Without the driver list there is no fallback; the header
                // path's failure is the one to report.
                let Some(driver) = phys
                    .dmp_info()
                    .and_then(|info| info.triage_drivers.iter().find(|d| d.base == ntoskrnl_va.0))
                    .cloned()
                else {
                    return Err(error);
                };

                Image::new(phys, symbols, kernel_dtb, ntoskrnl_va, arch)
                    .load_symbols_from_module_info(
                        &driver.name,
                        driver.time_date_stamp,
                        driver.size,
                    )?
            }
            Err(e) => return Err(e),
        };

        ntoskrnl.register_as_kernel();
        Ok(Self::from_kernel(ntoskrnl))
    }

    pub fn enumerate_processes(&self) -> Result<Vec<ProcessInfo>> {
        self.memoized(|memo| &mut memo.processes, || self.walk_processes())
    }

    fn walk_processes(&self) -> Result<Vec<ProcessInfo>> {
        let memory = self.ntoskrnl.memory();
        let mut span = EprocessSpan::new(self)?;

        let ps_initial_system_process: VirtAddr =
            self.ntoskrnl.symbol("PsInitialSystemProcess")?.read()?;
        let ps_active_process_head = self
            .ntoskrnl
            .symbol("PsActiveProcessHead")
            .ok()
            .map(|s| s.address());

        let mut processes = Vec::new();
        let mut visited = HashSet::new();

        let mut current_eprocess = ps_initial_system_process;

        // Cycle detection handles a corrupt list that loops; the cap handles
        // one that wanders through unrelated memory without repeating.
        const PROCESS_WALK_LIMIT: usize = 65_536;
        while processes.len() < PROCESS_WALK_LIMIT {
            if current_eprocess.0 == 0 || visited.contains(&current_eprocess.0) {
                break;
            }
            visited.insert(current_eprocess.0);

            span.read(&memory, current_eprocess)?;
            let dtb = span.dtb();
            if dtb == 0 {
                break;
            }

            processes.push(ProcessInfo {
                pid: span.pid(),
                name: self.process_name_from_image_file_name(
                    current_eprocess,
                    dtb,
                    span.image_file_name(),
                ),
                dtb,
                eprocess_va: current_eprocess,
                wow64_peb: self.wow64_peb(dtb, span.wow64_process()),
            });

            let flink = span.active_process_links_flink();
            if flink.0 == 0 || Some(flink) == ps_active_process_head {
                break;
            }

            current_eprocess = flink - span.active_process_links_offset;
            if current_eprocess == ps_initial_system_process {
                break;
            }
        }

        Ok(processes)
    }

    /// The process at `eprocess_va` without walking the process list: one
    /// EPROCESS span read plus the PEB walk only for a possibly truncated
    /// name.
    pub fn process_at(&self, eprocess_va: VirtAddr) -> Result<ProcessInfo> {
        let mut span = EprocessSpan::new(self)?;
        span.read(&self.ntoskrnl.memory(), eprocess_va)?;
        let dtb = span.dtb();
        Ok(ProcessInfo {
            pid: span.pid(),
            name: self.process_name_from_image_file_name(eprocess_va, dtb, span.image_file_name()),
            dtb,
            eprocess_va,
            wow64_peb: self.wow64_peb(dtb, span.wow64_process()),
        })
    }

    /// The process whose KVA-shadow user root is `user_root`
    /// (`_KPROCESS.UserDirectoryTableBase`), compared under `mask`. `None`
    /// when no process owns it or the kernel has no shadow roots.
    pub fn process_for_user_root(&self, user_root: Dtb, mask: u64) -> Option<ProcessInfo> {
        let types = self.ntoskrnl.types();
        let user_root_offset = types.layout("_EPROCESS").ok()?.field_offset("Pcb").ok()?
            + types
                .layout("_KPROCESS")
                .ok()?
                .field_offset("UserDirectoryTableBase")
                .ok()?;
        let memory = self.ntoskrnl.memory();
        self.enumerate_processes()
            .ok()?
            .into_iter()
            .find(|process| {
                memory
                    .read::<u64>(process.eprocess_va + user_root_offset)
                    .is_ok_and(|root| root & mask == user_root)
            })
    }

    /// The 32-bit PEB behind `_EPROCESS.WoW64Process`: since Windows 10 1511
    /// the pointer is to an `_EWOW64PROCESS` holding it, before that it was
    /// the PEB itself. Unreadable is reported as native rather than failing
    /// process enumeration.
    fn wow64_peb(&self, dtb: Dtb, wow64_process: Option<VirtAddr>) -> Option<VirtAddr> {
        let pointer = wow64_process?;
        let types = self.ntoskrnl.types_in(dtb);
        let peb = match types.struct_at("_EWOW64PROCESS", pointer) {
            Ok(ewow64) => ewow64.read_pointer("Peb").ok()?,
            Err(Error::StructNotFound(_)) => pointer,
            Err(_) => return None,
        };
        (!peb.is_zero()).then_some(peb)
    }

    /// Display name for the process at `eprocess_va` given its raw
    /// `EPROCESS.ImageFileName` bytes. The kernel keeps only the first 15
    /// bytes of the image name, so the PEB loader list (a page-walked read of
    /// user memory) is consulted only when the field is full and may be
    /// truncated; every shorter name is complete as is.
    fn process_name_from_image_file_name(
        &self,
        eprocess_va: VirtAddr,
        dtb: Dtb,
        image_file_name: &[u8],
    ) -> String {
        let len = image_file_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(image_file_name.len());
        if len == IMAGE_FILE_NAME_LEN
            && dtb != 0
            && let Ok(full) = self.full_process_name(eprocess_va, dtb)
        {
            return full;
        }
        if len == 0 {
            return "<unknown>".to_string();
        }
        String::from_utf8_lossy(&image_file_name[..len]).to_string()
    }

    /// Display name for the process at `eprocess_va` without walking the
    /// process list: the `ImageFileName` read plus, only for a possibly
    /// truncated name, the process DTB and PEB walk.
    pub fn process_name_at(&self, eprocess_va: VirtAddr) -> Option<String> {
        let mut span = EprocessSpan::new(self).ok()?;
        span.read(&self.ntoskrnl.memory(), eprocess_va).ok()?;
        if span.image_file_name()[0] == 0 {
            return None;
        }
        Some(self.process_name_from_image_file_name(
            eprocess_va,
            span.dtb(),
            span.image_file_name(),
        ))
    }

    fn full_process_name(&self, eprocess_va: VirtAddr, dtb: Dtb) -> Result<String> {
        // The process dtb maps both the kernel _EPROCESS and the user-space PEB
        // it points at, so the whole walk reads through one address space:
        // ntoskrnl's kernel types viewed in the process's space.
        let eprocess = self
            .ntoskrnl
            .types_in(dtb)
            .struct_at("_EPROCESS", eprocess_va)?;

        let peb = eprocess.follow("Peb")?;
        let image_base: VirtAddr = peb.read_field("ImageBaseAddress")?;
        if image_base.is_zero() {
            return Err(Error::MissingImageBase);
        }

        for record in peb.follow("Ldr")?.list(
            "InLoadOrderModuleList",
            "_LDR_DATA_TABLE_ENTRY",
            "InLoadOrderLinks",
        )? {
            let record = record?;
            let dll_base: VirtAddr = record.read_field("DllBase")?;
            if dll_base == image_base {
                return record.unicode_string("BaseDllName");
            }
        }

        Err(Error::MissingImage)
    }

    pub fn process_modules(&self, info: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
        self.process_modules_detail(info)
            .map(|detail| detail.modules)
    }

    /// One shared native/WOW64 loader-list walk for `lm`, `!dlls`, and the SDK.
    /// Partial entries and each list's termination are preserved for callers
    /// that need to diagnose a corrupt or truncated list.
    pub fn process_modules_detail(&self, info: &ProcessInfo) -> Result<ProcessModulesDetail> {
        self.memoized(
            |memo| memo.process_modules.entry(info.eprocess_va).or_default(),
            || self.walk_process_modules(info),
        )
    }

    fn walk_process_modules(&self, info: &ProcessInfo) -> Result<ProcessModulesDetail> {
        let types = self.ntoskrnl.types_in(info.dtb);
        let eprocess = types.struct_at("_EPROCESS", info.eprocess_va)?;
        let peb = eprocess.follow("Peb")?;
        if peb.addr().is_zero() {
            return Err(Error::MissingPEB);
        }
        let ldr = peb.follow("Ldr")?;
        let mut modules = Vec::new();
        let termination = if ldr.addr().is_zero() {
            ListTermination::Null
        } else {
            let head = ldr.embedded("InLoadOrderModuleList")?.addr();
            let layout = types.layout("_LDR_DATA_TABLE_ENTRY")?;
            let link_offset = layout.field_offset("InLoadOrderLinks")?;
            let pointer_size = usize::from(layout.pointer_size);
            let memory = self.ntoskrnl.memory_in(info.dtb);
            let mut cursor = ListCursor::new(head, MAX_LOADER_MODULES);
            cursor.advance(
                read_loader_pointer(&memory, head, pointer_size).map_err(|error| error.to_string()),
            );
            while let Some(link) = cursor.take_current() {
                let record_address = VirtAddr(link.0.wrapping_sub(link_offset));
                let record = types
                    .struct_with_layout(Arc::clone(&layout), record_address)
                    .prefetch();
                match module_info_from_record(&record) {
                    Ok(Some(module)) => modules.push(module),
                    Ok(None) => {}
                    Err(error) => {
                        cursor.advance(Err(error.to_string()));
                        break;
                    }
                }
                cursor.advance(
                    read_loader_pointer(&memory, record_address + link_offset, pointer_size)
                        .map_err(|error| error.to_string()),
                );
            }
            cursor.finish()
        };

        let mut wow64_termination = None;
        if let Some(peb32) = info.wow64_peb {
            let (modules32, termination32) = self.process_modules32(info.dtb, peb32)?;
            wow64_termination = Some(termination32);
            // Both lists carry the executable itself (one mapping, x86 code)
            // and an ntdll (two: the 32-bit copy is addressed as `ntdll32!`,
            // as WinDbg's wow64exts does).
            for mut module in modules32 {
                if let Some(native) = modules
                    .iter_mut()
                    .find(|native| native.base_address == module.base_address)
                {
                    native.is_32bit = true;
                    continue;
                }
                if modules
                    .iter()
                    .any(|native| native.short_name == module.short_name)
                {
                    module.short_name.push_str("32");
                }
                modules.push(module);
            }
        }

        Ok(ProcessModulesDetail {
            modules,
            termination,
            wow64_termination,
        })
    }

    /// The 32-bit loader list of a WOW64 process. `_PEB_LDR_DATA32` and
    /// `_LDR_DATA_TABLE_ENTRY32` are not in the kernel's PDB and the 32-bit
    /// ntdll's is not loaded before this walk finds it, so the entry layout
    /// is the fixed x86 ABI (unchanged since Windows 2000): `DllBase` +0x18,
    /// `EntryPoint` +0x1c, `SizeOfImage` +0x20, `FullDllName` +0x24,
    /// `BaseDllName` +0x2c, `TimeDateStamp` +0x44.
    fn process_modules32(
        &self,
        dtb: Dtb,
        peb32: VirtAddr,
    ) -> Result<(Vec<ModuleInfo>, ListTermination)> {
        const IN_LOAD_ORDER_MODULE_LIST: u64 = 0x0c;
        const ENTRY_LEN: usize = 0x48;

        let types = self.ntoskrnl.types_in(dtb);
        let ldr: u32 = types.struct_at("_PEB32", peb32)?.read_field("Ldr")?;
        if ldr == 0 {
            return Ok((Vec::new(), ListTermination::Null));
        }
        let memory = self.ntoskrnl.memory_in(dtb);
        let head = VirtAddr(u64::from(ldr) + IN_LOAD_ORDER_MODULE_LIST);
        let mut cursor = ListCursor::new(head, MAX_LOADER_MODULES);
        cursor.advance(read_loader_pointer(&memory, head, 4).map_err(|error| error.to_string()));
        let mut modules = Vec::new();
        while let Some(current) = cursor.take_current() {
            let mut entry = [0u8; ENTRY_LEN];
            if let Err(error) = memory.read_bytes(current, &mut entry) {
                cursor.advance(Err(error.to_string()));
                break;
            }
            let u32_at =
                |offset: usize| u32::from_le_bytes(entry[offset..offset + 4].try_into().unwrap());
            cursor.advance(Ok(VirtAddr(u64::from(u32_at(0)))));

            let dll_base = u32_at(0x18);
            if dll_base == 0 {
                continue;
            }
            let name = read_unicode32(
                &memory,
                usize::from(u16::from_le_bytes([entry[0x2c], entry[0x2d]])),
                u32_at(0x30),
            )
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "<unknown>".to_string());
            let mut module = ModuleInfo::new(name, VirtAddr(u64::from(dll_base)), u32_at(0x20))
                .with_time_date_stamp(u32_at(0x44));
            module.path = read_unicode32(
                &memory,
                usize::from(u16::from_le_bytes([entry[0x24], entry[0x25]])),
                u32_at(0x28),
            )
            .filter(|path| !path.is_empty());
            module.is_32bit = true;
            let entry_point = u32_at(0x1c);
            if entry_point != 0 {
                module.entry_point = Some(VirtAddr(u64::from(entry_point)));
            }
            modules.push(module);
        }
        Ok((modules, cursor.finish()))
    }

    pub fn kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        self.memoized(
            |memo| &mut memo.kernel_modules,
            || self.walk_kernel_modules(),
        )
    }

    fn walk_kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        let head = self.ntoskrnl.symbol("PsLoadedModuleList")?;
        // At a reboot's first boot notification the list is not built yet,
        // but the kernel itself is loaded; stacks unwind through it.
        if head.read::<VirtAddr>()?.is_zero() {
            return Ok(vec![ModuleInfo::new(
                "ntoskrnl.exe".to_string(),
                self.ntoskrnl.base_address,
                self.ntoskrnl.binary_size() as u32,
            )]);
        }
        let head = head.address();

        // The kernel uses the _KLDR variant; fall back to _LDR if it's absent
        let record_type = if self
            .ntoskrnl
            .types()
            .layout("_KLDR_DATA_TABLE_ENTRY")
            .is_ok()
        {
            "_KLDR_DATA_TABLE_ENTRY"
        } else {
            "_LDR_DATA_TABLE_ENTRY"
        };

        let mut modules = Vec::new();
        for record in self
            .ntoskrnl
            .types()
            .list_at(head, record_type, "InLoadOrderLinks")?
        {
            if let Some(module) = module_info_from_record(&record?)? {
                modules.push(module);
            }
        }

        Ok(modules)
    }

    pub fn populate_kernel_module_versions(&self, modules: &mut [ModuleInfo]) {
        let memory = self.ntoskrnl.memory();
        populate_module_versions(modules, &memory);
    }

    pub fn populate_process_module_versions(&self, modules: &mut [ModuleInfo], info: &ProcessInfo) {
        populate_module_versions(modules, &self.ntoskrnl.memory_in(info.dtb));
    }

    fn is_session_space(addr: VirtAddr) -> bool {
        let prefix = addr.0 >> 44;
        prefix == 0xFFFF8 || prefix == 0xFFFF9 || prefix == 0xFFFFA
    }

    /// Load symbols for `modules` under `dtb`: discover each module's PDB
    /// identity from guest memory, acquire the PDBs (cache, local stores,
    /// symbol servers), index them. Blocks for the whole of it; the stop
    /// render uses [`Guest::load_module_symbols_or_fetch_later`] instead so a
    /// stack walk through an uncached module never waits on the network.
    pub fn load_module_symbols(
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        skip_session_space: bool,
        arch: Arch,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut report = ModuleSymbolLoadReport::new(modules.len());
        let plan = Self::plan_module_symbol_loads(
            phys,
            symbols,
            modules,
            dtb,
            skip_session_space,
            arch,
            &mut report,
        );
        let stale_identities =
            Self::complete_module_symbol_loads(symbols, plan, dtb, &mut report, false);

        // Modules whose remembered PDB no longer resolves: forget the record
        // and rediscover them from the target.
        if !stale_identities.is_empty() {
            for module in &stale_identities {
                symbols.forget_module_identity(module);
            }
            report.absorb(Self::load_module_symbols(
                phys,
                symbols,
                stale_identities,
                dtb,
                skip_session_space,
                arch,
            )?);
        }

        Ok(report)
    }

    /// The stop-render variant of [`Guest::load_module_symbols`]: index what
    /// is already on disk now, and hand anything that needs a download to a
    /// background thread. Frames in a module being fetched render as
    /// `module+offset` until it lands; the store's load generation moves when
    /// it does, so the session re-resolves deferred breakpoints and the next
    /// backtrace shows names. Start and finish are reported through the
    /// store's notices.
    ///
    /// Discovery (guest memory) runs on the caller's thread: a KD-mediated
    /// memory source is only usable from the thread that owns the transport.
    /// A remembered identity that turns out stale is rediscovered once, here,
    /// before anything is handed off.
    pub fn load_module_symbols_or_fetch_later(
        phys: &PhysMem,
        symbols: &Arc<SymbolStore>,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        arch: Arch,
    ) -> ModuleSymbolLoadReport {
        let mut report = ModuleSymbolLoadReport::new(modules.len());
        let mut plan =
            Self::plan_module_symbol_loads(phys, symbols, modules, dtb, false, arch, &mut report);
        let mut deferred = plan.take_fetches();
        let stale = Self::complete_module_symbol_loads(symbols, plan, dtb, &mut report, false);
        if !stale.is_empty() {
            for module in &stale {
                symbols.forget_module_identity(module);
            }
            let mut replan =
                Self::plan_module_symbol_loads(phys, symbols, stale, dtb, false, arch, &mut report);
            deferred.absorb(replan.take_fetches());
            for module in
                Self::complete_module_symbol_loads(symbols, replan, dtb, &mut report, false)
            {
                Self::apply_module_symbol_status(
                    symbols,
                    &mut report,
                    dtb,
                    &module,
                    ModuleSymbolStatus::Failed(
                        "remembered PDB no longer matches the image".to_string(),
                    ),
                );
            }
        }

        if !deferred.needs_fetch() {
            return report;
        }
        let names = deferred.module_names();
        for module in deferred.modules() {
            Self::apply_module_symbol_status(
                symbols,
                &mut report,
                dtb,
                module,
                ModuleSymbolStatus::Fetching,
            );
        }
        symbols.push_notice(format!(
            "fetching symbols for {} in the background; frames there show module+offset \
             until it finishes (lm shows `fetching`)",
            names.join(", ")
        ));

        let store = Arc::clone(symbols);
        let spawned = std::thread::Builder::new()
            .name("ntoseye-symbol-fetch".to_string())
            .spawn(move || {
                let symbols = store;
                let mut report = ModuleSymbolLoadReport::new(deferred.len());
                let stale =
                    Self::complete_module_symbol_loads(&symbols, deferred, dtb, &mut report, true);
                for module in &stale {
                    symbols.forget_module_identity(module);
                    Self::apply_module_symbol_status(
                        &symbols,
                        &mut report,
                        dtb,
                        module,
                        ModuleSymbolStatus::Failed(
                            "remembered PDB no longer matches the image; run .reload <module>"
                                .to_string(),
                        ),
                    );
                }
                symbols.push_notice(format!(
                    "background symbol fetch finished for {}: {} loaded, {} failed",
                    names.join(", "),
                    report.loaded,
                    report.failed + report.no_pdb
                ));
            });
        if let Err(error) = spawned {
            symbols.push_notice(format!("could not start background symbol fetch: {error}"));
        }
        report
    }

    /// Discovery half of a symbol load: read each module's debug directory
    /// from guest memory (or its remembered identity) and sort the modules
    /// into loads whose PDB is already on disk, loads that need a download,
    /// and modules whose headers were unreadable so the image itself must be
    /// fetched to learn the PDB identity. Touches guest memory; never the
    /// network.
    fn plan_module_symbol_loads(
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        skip_session_space: bool,
        arch: Arch,
        report: &mut ModuleSymbolLoadReport,
    ) -> ModuleSymbolPlan {
        let mut plan = ModuleSymbolPlan::default();

        for module in modules {
            if skip_session_space && Self::is_session_space(module.base_address) {
                Self::apply_module_symbol_status(
                    symbols,
                    report,
                    dtb,
                    &module,
                    ModuleSymbolStatus::Skipped,
                );
                continue;
            }

            match symbols.extract_download_job(phys, dtb, &module, arch) {
                Ok(ModuleSymbolDiscovery::Ready { job, guid, source }) => {
                    plan.queue(
                        symbols,
                        ModuleSymbolLoad::new(job, guid, source, module, dtb),
                    );
                }
                Ok(ModuleSymbolDiscovery::NeedsImage { image_job }) => {
                    plan.image_jobs.push((image_job, module));
                }
                Err(_e) if module.time_date_stamp.is_some() => {
                    let tds = module.time_date_stamp.unwrap();
                    match SymbolStore::build_image_download_job(&module.name, tds, module.size) {
                        Ok(image_job) => plan.image_jobs.push((image_job, module)),
                        Err(e) => Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        ),
                    }
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }
        plan
    }

    /// Acquisition half of a symbol load: download images and PDBs the plan
    /// asked for, then index everything that is on disk. Files and network
    /// only, so it may run off the session thread. Returns the modules whose
    /// remembered identity no longer resolves; the caller decides whether to
    /// rediscover them (needs guest memory) or give up.
    fn complete_module_symbol_loads(
        symbols: &SymbolStore,
        plan: ModuleSymbolPlan,
        dtb: Dtb,
        report: &mut ModuleSymbolLoadReport,
        quiet: bool,
    ) -> Vec<ModuleInfo> {
        let ModuleSymbolPlan {
            mut ready,
            mut downloads,
            image_jobs,
        } = plan;

        let image_results = download_jobs_parallel(
            image_jobs.iter().map(|(job, _)| job.clone()).collect(),
            quiet,
        );
        for ((image_job, module), result) in image_jobs.into_iter().zip(image_results) {
            match result {
                Ok(_) => match symbols.extract_download_job_from_image_file(&image_job.path) {
                    Ok(Some((job, guid))) => {
                        let load = ModuleSymbolLoad::new(
                            job,
                            guid,
                            ModuleSymbolSource::Image,
                            module,
                            dtb,
                        );
                        if symbols.has_matching_pdb(&load.job) || load.job.cached_pdb_matches() {
                            ready.push(load);
                        } else {
                            downloads.push(load);
                        }
                    }
                    Ok(None) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::MissingDebugInfo,
                        );
                    }
                    Err(e) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                },
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        let download_results = download_jobs_parallel(
            downloads.iter().map(|load| load.job.clone()).collect(),
            quiet,
        );
        let mut stale_identities: Vec<ModuleInfo> = Vec::new();
        for (load, result) in downloads.into_iter().zip(download_results) {
            match result {
                Ok(_) => ready.push(load),
                Err(_) if matches!(load.source, ModuleSymbolSource::Identity) => {
                    stale_identities.push(load.module);
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &load.module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        if !ready.is_empty() {
            let pb = if quiet {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(ready.len() as u64)
            };
            pb.set_style(
                ProgressStyle::with_template("Indexing [{bar:40}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("#-"),
            );

            // Two modules can share a PDB guid, and indexing one guid is
            // serialized behind a per-guid `OnceLock` inside the symbol store.
            // Indexing also nests rayon, and a worker that blocks in a nested
            // region steals other items from this very loop: if it picked up a
            // second module with the guid it is already initializing, it would
            // park on that `OnceLock` waiting for itself. Give the parallel
            // pass one module per guid and run any duplicates afterwards, where
            // they take the already-indexed fast path.
            let (first_per_guid, duplicate_guids) =
                partition_first_occurrence(ready, |load| load.guid);

            let mut results = first_per_guid
                .into_par_iter()
                .map(|load| {
                    let result = symbols.load_downloaded_pdb(&load);
                    pb.inc(1);
                    (load, result)
                })
                .collect::<Vec<_>>();
            results.extend(duplicate_guids.into_iter().map(|load| {
                let result = symbols.load_downloaded_pdb(&load);
                pb.inc(1);
                (load, result)
            }));

            pb.finish_and_clear();

            for (load, result) in results {
                match result {
                    Ok(_) => {
                        report.record_status(&ModuleSymbolStatus::Loaded);
                        report.record_diagnostics(
                            &load.module.name,
                            symbols.index_diagnostics(load.guid),
                        );
                        if !matches!(load.source, ModuleSymbolSource::Identity) {
                            symbols.remember_module_identity(&load.module, &load.job);
                        }
                    }
                    Err(_) if matches!(load.source, ModuleSymbolSource::Identity) => {
                        stale_identities.push(load.module);
                    }
                    Err(e) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &load.module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                }
            }
        }

        stale_identities
    }

    pub fn load_all_kernel_module_symbols(
        &self,
        phys: &PhysMem,
        symbols: &SymbolStore,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut modules = self.kernel_modules()?;
        if !modules
            .iter()
            .any(|module| module.base_address == self.ntoskrnl.base_address)
        {
            let size = self.ntoskrnl.binary_size().try_into().unwrap_or(u32::MAX);
            if size != 0 {
                modules.insert(
                    0,
                    ModuleInfo::new("ntoskrnl.exe".to_string(), self.ntoskrnl.base_address, size),
                );
            }
        }
        let dtb = self.ntoskrnl.dtb();
        Self::load_module_symbols(phys, symbols, modules, dtb, true, self.ntoskrnl.arch())
    }

    pub fn load_missing_kernel_module_symbols(
        &self,
        phys: &PhysMem,
        symbols: &SymbolStore,
    ) -> Result<ModuleSymbolLoadReport> {
        let dtb = self.ntoskrnl.dtb();
        let modules = self.kernel_modules()?;
        if modules.is_empty() {
            return Ok(ModuleSymbolLoadReport::new(0));
        }

        let unloaded = symbols.retain_modules_for_dtb(dtb, &modules);
        let missing = modules
            .into_iter()
            .filter(|module| {
                symbols
                    .module_symbol_status(dtb, module.base_address)
                    .is_none()
            })
            .collect::<Vec<_>>();

        let mut report =
            Self::load_module_symbols(phys, symbols, missing, dtb, true, self.ntoskrnl.arch())?;
        report.unloaded = unloaded;
        Ok(report)
    }

    pub fn load_all_process_module_symbols(
        &self,
        phys: &PhysMem,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<ModuleSymbolLoadReport> {
        let modules = self.process_modules(info)?;
        let dtb = info.dtb;
        Self::load_module_symbols(phys, symbols, modules, dtb, false, self.ntoskrnl.arch())
    }

    /// Load symbols for an explicit set of modules under `dtb`. Used to lazily
    /// resolve the modules a backtrace touches (e.g. user-mode frames in a
    /// process we never attached to). Callers filter out already-attempted
    /// modules; this loads whatever it is given.
    pub fn load_symbols_for_modules(
        &self,
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
    ) -> Result<ModuleSymbolLoadReport> {
        Self::load_module_symbols(phys, symbols, modules, dtb, false, self.ntoskrnl.arch())
    }
}

/// Split `items` into the first item per distinct key and every later item
/// sharing a key already seen, preserving input order in both halves.
///
/// Used to keep a parallel pass to one item per key while still processing the
/// rest; nothing is dropped.
fn partition_first_occurrence<T, K: Eq + std::hash::Hash>(
    items: Vec<T>,
    key: impl Fn(&T) -> K,
) -> (Vec<T>, Vec<T>) {
    let mut first = Vec::with_capacity(items.len());
    let mut rest = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(key(&item)) {
            first.push(item);
        } else {
            rest.push(item);
        }
    }
    (first, rest)
}

#[cfg(test)]
mod tests {
    use super::{
        IMAGE_BLOCK, ModuleExportInfo, ModuleSymbolLoadReport, PE_HEADER_PROBE, PeImage,
        find_ntoskrnl_va, partition_first_occurrence, read_pe_exports, read_pe_header_page,
        read_pe_image,
    };
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::memory::{AddressSpace, DTB_IDENTITY};
    use crate::symbols::SymbolIndexDiagnostic;
    use crate::types::{PhysAddr, VirtAddr};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Indexing one PDB guid is serialized behind a per-guid `OnceLock`, and a
    /// rayon worker blocked in a nested parallel region steals other items
    /// from the same loop. Two modules sharing a guid must therefore never be
    /// in the parallel pass together, and neither may be dropped.
    #[test]
    fn same_key_items_are_deferred_out_of_the_parallel_pass() {
        let modules = vec![
            (7u32, "a.sys"),
            (9, "b.sys"),
            (7, "c.sys"),
            (8, "d.sys"),
            (7, "e.sys"),
            (9, "f.sys"),
        ];

        let (first, rest) = partition_first_occurrence(modules, |(guid, _)| *guid);

        assert_eq!(first, vec![(7, "a.sys"), (9, "b.sys"), (8, "d.sys")]);
        assert_eq!(rest, vec![(7, "c.sys"), (7, "e.sys"), (9, "f.sys")]);
    }

    /// Identity-mapped memory holding one image at `base`; reads outside it
    /// fail like an unmapped page. Counts the bytes handed out.
    struct ImageMemory {
        base: u64,
        bytes: Vec<u8>,
        read: AtomicUsize,
        /// Bytes past this offset read as unmapped.
        readable: AtomicUsize,
    }

    impl ImageMemory {
        fn new(base: u64, bytes: Vec<u8>) -> Self {
            Self {
                base,
                readable: AtomicUsize::new(bytes.len()),
                bytes,
                read: AtomicUsize::new(0),
            }
        }

        fn bytes_read(&self) -> usize {
            self.read.load(Ordering::Relaxed)
        }
    }

    impl MemoryOps<PhysAddr> for ImageMemory {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let start = addr
                .checked_sub(self.base)
                .filter(|start| {
                    start + buf.len() as u64 <= self.readable.load(Ordering::Relaxed) as u64
                })
                .ok_or(Error::BadPhysicalAddress(addr))? as usize;
            buf.copy_from_slice(&self.bytes[start..start + buf.len()]);
            self.read.fetch_add(buf.len(), Ordering::Relaxed);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    fn open_image(memory: &Arc<ImageMemory>) -> PeImage {
        let memory = Arc::clone(memory);
        read_pe_image(VirtAddr(memory.base), move |address, buf| {
            AddressSpace::new(&memory, DTB_IDENTITY).read_bytes(address, buf)
        })
        .unwrap()
    }

    /// A PE32+ image with `.text` at 0x1000 and `.rdata` at 0x2000, each one
    /// page, filled with distinct bytes.
    fn synthetic_image() -> Vec<u8> {
        synthetic_image_with_pe_at(0x80)
    }

    fn synthetic_image_with_pe_at(pe: usize) -> Vec<u8> {
        let mut image = vec![0u8; 0x3000];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        image[pe..pe + 4].copy_from_slice(b"PE\0\0");
        image[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        image[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
        image[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let opt = pe + 24;
        image[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        image[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        image[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        image[opt + 60..opt + 64].copy_from_slice(&0x1000u32.to_le_bytes());
        image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let sections = opt + 240;
        for (index, (name, va, fill)) in [
            (b".text\0\0\0", 0x1000u32, 0xccu8),
            (b".rdata\0\0", 0x2000, 0xdd),
        ]
        .into_iter()
        .enumerate()
        {
            let header = sections + 40 * index;
            image[header..header + 8].copy_from_slice(name);
            image[header + 8..header + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            image[header + 12..header + 16].copy_from_slice(&va.to_le_bytes());
            image[header + 16..header + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            image[header + 20..header + 24].copy_from_slice(&va.to_le_bytes());
            image[va as usize..va as usize + 0x1000].fill(fill);
        }
        image
    }

    /// Opening an image costs the header probe; a lookup fetches the one
    /// block it lands in, and a second lookup in that block costs nothing.
    #[test]
    fn lazy_image_fetches_blocks_on_first_use() {
        let memory = Arc::new(ImageMemory::new(0x10_0000, synthetic_image()));
        let image = open_image(&memory);
        assert!(!image.is_complete());
        assert_eq!(memory.bytes_read(), PE_HEADER_PROBE);

        assert_eq!(&image.read(0x2200, 0x100).unwrap()[..], &[0xdd; 0x100][..]);
        assert_eq!(memory.bytes_read(), PE_HEADER_PROBE + IMAGE_BLOCK);
        assert_eq!(&image.read(0x2300, 0x10).unwrap()[..], &[0xdd; 0x10][..]);
        assert_eq!(memory.bytes_read(), PE_HEADER_PROBE + IMAGE_BLOCK);

        // A range spanning two blocks is stitched from both: the header
        // page's tail and the first bytes of `.text`.
        let across = image.read(2 * IMAGE_BLOCK - 4, 8).unwrap();
        assert_eq!(&across[..4], &[0; 4]);
        assert_eq!(&across[4..], &[0xcc; 4]);
        assert!(image.read(0x2ff0, 0x11).is_none());
    }

    /// A block the target refuses is a hole: the read reports it rather
    /// than serving zeros, and it is asked for again rather than remembered,
    /// so a page that is resident by the next lookup is served.
    #[test]
    fn lazy_image_reports_unreadable_blocks() {
        let memory = Arc::new(ImageMemory::new(0x10_0000, synthetic_image()));
        memory.readable.store(0x2000, Ordering::Relaxed);
        let image = open_image(&memory);

        assert!(image.is_present(0x1000, 0x10));
        assert!(!image.is_present(0x2000, 4));
        assert!(image.read(0x1ff0, 0x20).is_none());

        memory.readable.store(0x3000, Ordering::Relaxed);
        assert_eq!(&image.read(0x2000, 4).unwrap()[..], &[0xdd; 4][..]);
    }

    /// The header probe alone covers a normally linked image; a section table
    /// that runs past the probe is completed by a second read instead of
    /// being parsed from zeros.
    #[test]
    fn read_pe_header_page_extends_past_probe_only_when_needed() {
        let base = 0x10_0000u64;
        let memory = ImageMemory::new(base, synthetic_image());
        let space = AddressSpace::new(&memory, DTB_IDENTITY);
        let header = read_pe_header_page(VirtAddr(base), &space).unwrap();
        assert_eq!(memory.bytes_read(), PE_HEADER_PROBE);
        assert_eq!(&header[..PE_HEADER_PROBE], &memory.bytes[..PE_HEADER_PROBE]);

        let late_pe = PE_HEADER_PROBE - 0x40;
        let memory = ImageMemory::new(base, synthetic_image_with_pe_at(late_pe));
        let space = AddressSpace::new(&memory, DTB_IDENTITY);
        let header = read_pe_header_page(VirtAddr(base), &space).unwrap();
        let table_end = late_pe + 24 + 240 + 2 * 40;
        assert_eq!(memory.bytes_read(), table_end);
        assert_eq!(&header[..table_end], &memory.bytes[..table_end]);
        assert!(header[table_end..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn symbol_report_preserves_index_diagnostics_and_total_count() {
        let mut report = ModuleSymbolLoadReport::new(1);
        let diagnostics = (0..70)
            .map(|index| SymbolIndexDiagnostic {
                phase: "line iteration",
                compiland: Some(format!("{index}.obj")),
                message: "malformed line record".to_string(),
            })
            .collect();
        report.record_diagnostics("driver.sys", diagnostics);

        assert_eq!(report.diagnostic_count, 70);
        assert_eq!(report.diagnostics.len(), 64);
        assert_eq!(report.diagnostics[0].module, "driver.sys");
        assert_eq!(report.diagnostics[0].compiland.as_deref(), Some("0.obj"));
    }

    /// `synthetic_image` with an export directory in `.rdata`: ordinal base
    /// 5, three functions (a named one, a forwarder, an ordinal-only one),
    /// and a name table whose second entry points at `name_index`.
    fn image_with_exports(name_index: u16) -> Vec<u8> {
        const DIRECTORY: usize = 0x2000;
        let mut image = synthetic_image();
        image[DIRECTORY..0x3000].fill(0);
        let put = |image: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        let opt = 0x80 + 24;
        put(&mut image, opt + 112, &(DIRECTORY as u32).to_le_bytes());
        put(&mut image, opt + 116, &0x500u32.to_le_bytes());
        for (offset, value) in [
            (16, 5u32),
            (20, 3),
            (24, 2),
            (28, 0x2100),
            (32, 0x2200),
            (36, 0x2300),
        ] {
            put(&mut image, DIRECTORY + offset, &value.to_le_bytes());
        }
        for (index, rva) in [0x1010u32, 0x2400, 0x1020].into_iter().enumerate() {
            put(&mut image, 0x2100 + 4 * index, &rva.to_le_bytes());
        }
        put(&mut image, 0x2200, &0x2410u32.to_le_bytes());
        put(&mut image, 0x2204, &0x2420u32.to_le_bytes());
        put(&mut image, 0x2300, &0u16.to_le_bytes());
        put(&mut image, 0x2302, &name_index.to_le_bytes());
        put(&mut image, 0x2400, b"OTHER.Func\0");
        put(&mut image, 0x2410, b"Alpha\0");
        put(&mut image, 0x2420, b"Forwarded\0");
        image
    }

    #[test]
    fn an_image_that_exports_nothing_has_no_exports() {
        let mut image = image_with_exports(1);
        let opt = 0x80 + 24;
        image[opt + 112..opt + 120].fill(0);
        assert_eq!(
            read_pe_exports(&PeImage::complete(image), VirtAddr(0x10_0000)).unwrap(),
            []
        );
    }

    #[test]
    fn exports_cover_named_forwarded_and_ordinal_only_entries() {
        let base = VirtAddr(0x10_0000);
        let exports = read_pe_exports(&PeImage::complete(image_with_exports(1)), base).unwrap();
        assert_eq!(
            exports,
            [
                ModuleExportInfo {
                    name: Some("Alpha".into()),
                    ordinal: 5,
                    address: Some(base + 0x1010u64),
                    forwarder: None,
                },
                ModuleExportInfo {
                    name: Some("Forwarded".into()),
                    ordinal: 6,
                    address: None,
                    forwarder: Some("OTHER.Func".into()),
                },
                ModuleExportInfo {
                    name: None,
                    ordinal: 7,
                    address: Some(base + 0x1020u64),
                    forwarder: None,
                },
            ]
        );
    }

    #[test]
    fn export_name_past_the_function_table_is_an_error() {
        let image = PeImage::complete(image_with_exports(3));
        assert!(read_pe_exports(&image, VirtAddr(0x10_0000)).is_err());
    }

    /// Physical memory holding only the 4 KiB pages written to it.
    #[derive(Default)]
    struct SparsePhys(HashMap<u64, Box<[u8; 0x1000]>>);

    impl SparsePhys {
        fn write_u64(&mut self, addr: u64, value: u64) {
            let page = self
                .0
                .entry(addr & !0xfff)
                .or_insert_with(|| Box::new([0; 0x1000]));
            let at = (addr & 0xfff) as usize;
            page[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }

        fn write_ntoskrnl_header(&mut self, frame: u64) {
            self.write_u64(frame, 0x0000_0090_5a4d);
            self.write_u64(frame + 0x200, u64::from_le_bytes(*b"POOLCODE"));
        }
    }

    impl MemoryOps<PhysAddr> for SparsePhys {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            for (offset, byte) in buf.iter_mut().enumerate() {
                let at = addr + offset as u64;
                let page = self
                    .0
                    .get(&(at & !0xfff))
                    .ok_or(Error::BadPhysicalAddress(at))?;
                *byte = page[(at & 0xfff) as usize];
            }
            Ok(())
        }

        fn write_bytes(&self, addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(addr))
        }
    }

    /// The AMD64 kernel-image scan covers `0xffff_f800_0000_0000` through
    /// `0xffff_f808_0000_0000` inclusive: an image mapped at the upper bound is
    /// found, one mapped a slot past it is not.
    #[test]
    fn ntoskrnl_scan_ends_at_its_upper_bound() {
        const DTB: u64 = 0x1000;
        const PDPT: u64 = 0x2000;
        // Present, writable, supervisor, large page, no-execute.
        const KERNEL_LARGE_PAGE: u64 = 0x80 | 0b11 | (1 << 63);
        let upper = VirtAddr(0xffff_f808_0000_0000);
        let mut phys = SparsePhys::default();
        phys.write_u64(DTB + 8 * upper.pml4_index() as u64, PDPT | 0b11);

        let past = upper.pdpt_index() as u64 + 1;
        phys.write_u64(PDPT + 8 * past, 0x8000_0000 | KERNEL_LARGE_PAGE);
        phys.write_ntoskrnl_header(0x8000_0000);
        assert_eq!(find_ntoskrnl_va(DTB, &phys).unwrap(), None);

        let at_bound = upper.pdpt_index() as u64;
        phys.write_u64(PDPT + 8 * at_bound, 0x4000_0000 | KERNEL_LARGE_PAGE);
        phys.write_ntoskrnl_header(0x4000_0000);
        assert_eq!(find_ntoskrnl_va(DTB, &phys).unwrap(), Some(upper));
    }
}
