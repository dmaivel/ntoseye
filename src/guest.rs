use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    memory::{self, AddressSpace, DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::{
        DownloadJob, FieldInfo, ModuleSymbolDiscovery, ModuleSymbolLoad, ModuleSymbolSource,
        ModuleSymbolStatus, ParsedType, SymbolIndexDiagnostic, SymbolStore, TypeInfo,
        download_jobs_parallel,
    },
    target::DriverObjectInfo,
    types::*,
};
use indicatif::{ProgressBar, ProgressStyle};
use pelite::pe64::{Pe, PeFile, PeView};
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zerocopy::{FromBytes, IntoBytes};

/// `EPROCESS.ImageFileName` capacity: the kernel keeps this many bytes of the
/// image name, unterminated when the name is at least this long.
const IMAGE_FILE_NAME_LEN: usize = 15;

/// used for enumeration without loading full WinObject
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub name: String,
    pub dtb: Dtb,
    pub eprocess_va: VirtAddr,
}

/// module metadata from PEB LDR list
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub short_name: String,
    pub base_address: VirtAddr,
    pub size: u32,
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
            base_address,
            size,
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
        self.diagnostic_count += other.diagnostic_count;
        self.diagnostics.extend(other.diagnostics);
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
fn pe_headers_end(probe: &[u8]) -> Option<usize> {
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

/// Open a module image in guest memory: the headers are read now, the rest
/// on demand through `read`, which reads `buf.len()` bytes at a virtual
/// address of the module's address space.
pub fn read_pe_image(
    base_address: VirtAddr,
    read: impl Fn(VirtAddr, &mut [u8]) -> Result<()> + Send + Sync + 'static,
) -> Result<PeImage> {
    let headers = read_pe_header_page_with(&|address, buf| read(base_address + address, buf))?;
    let size = PeView::from_bytes(&headers)?.optional_header().SizeOfImage as usize;
    Ok(PeImage {
        size,
        body: ImageBody::Lazy(LazyImage {
            headers: Box::new(headers),
            read: Box::new(move |rva, buf| read(base_address + rva as u64, buf)),
            blocks: Mutex::new(HashMap::new()),
        }),
    })
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
    let optional_header = file.optional_header();

    let total_size = optional_header.SizeOfImage as usize;
    let mut image_buffer = vec![0u8; total_size];

    let headers_size = (optional_header.SizeOfHeaders as usize)
        .min(total_size)
        .min(data.len());
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
    obj: &'a WinObject,
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

/// The address space a module lives in: AArch64 kernel VAs walk `kernel_dtb`
/// (TTBR1) while `dtb` stays the process root.
fn object_address_space(
    phys: &Arc<PhysMem>,
    dtb: Dtb,
    kernel_dtb: Dtb,
    arch: Arch,
) -> AddressSpace<'_, Arc<PhysMem>> {
    match arch {
        Arch::Amd64 => AddressSpace::new(phys, dtb),
        Arch::Arm64 => AddressSpace::new_arm64(phys, dtb, kernel_dtb),
    }
}

/// A structured view into a loaded module's memory: it carries its own address
/// space (`dtb`) and the handles needed to read and resolve symbols/types
/// (`kvm`, `symbols`), so navigation methods don't take them as arguments. The
/// handles are shared (`Arc`), not borrowed; a `WinObject` can't borrow its
/// `Target` siblings, but it can own a refcounted handle to them.
pub struct WinObject {
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

impl WinObject {
    pub fn new(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Self {
        Self::new_with_arch(phys, symbols, dtb, base_address, Arch::Amd64)
    }

    pub fn new_with_arch(
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

    /// Mark this object's module as the kernel in the shared symbol store, so
    /// type/enum layout lookups prefer it across address spaces. Call after
    /// [`load_symbols`](Self::load_symbols) so `guid` is populated.
    pub fn register_as_kernel(&self) {
        self.symbols.set_kernel_guid(self.guid);
    }

    /// `SizeOfImage` of the module (0 until [`view`](Self::view) has run).
    pub fn binary_size(&self) -> usize {
        self.headers
            .as_deref()
            .and_then(|headers| PeView::from_bytes(headers).ok())
            .map_or(0, |view| view.optional_header().SizeOfImage as usize)
    }

    /// A sibling object sharing this one's physical-memory and symbol handles,
    /// at a new base in a possibly different address space. Symbols are not
    /// loaded yet (`guid` is `None`).
    pub fn sibling(&self, dtb: Dtb, base_address: VirtAddr) -> WinObject {
        WinObject {
            base_address,
            dtb,
            arch: self.arch,
            kernel_dtb: self.kernel_dtb,
            headers: None,
            image: Mutex::new(None),
            guid: None,
            phys: Arc::clone(&self.phys),
            symbols: Arc::clone(&self.symbols),
        }
    }

    pub fn address_of(&self, rva: impl Into<u64>) -> VirtAddr {
        self.base_address + rva.into()
    }

    fn address_space<'a>(
        &self,
        phys: &'a Arc<PhysMem>,
        dtb: Dtb,
    ) -> AddressSpace<'a, Arc<PhysMem>> {
        object_address_space(phys, dtb, self.kernel_dtb, self.arch)
    }

    pub fn memory(&self) -> AddressSpace<'_, Arc<PhysMem>> {
        self.address_space(&self.phys, self.dtb)
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
            let (phys, dtb, kernel_dtb, arch) =
                (Arc::clone(&self.phys), self.dtb, self.kernel_dtb, self.arch);
            let image = read_pe_image(self.base_address, move |address, buf| {
                object_address_space(&phys, dtb, kernel_dtb, arch).read_bytes(address, buf)
            })
            .ok()?;
            *cached = Some(Arc::new(image));
        }
        cached.clone()
    }

    /// Resolve this object's struct/type namespace, read in its own address
    /// space. Use [`types_in`](Self::types_in) to read the same types from a
    /// different `dtb` (e.g. ntoskrnl's kernel types against a process's space).
    pub fn types(&self) -> Types<'_> {
        Types {
            obj: self,
            dtb: self.dtb,
        }
    }

    /// Like [`types`](Self::types), but reads against `dtb` instead of this
    /// object's own, for kernel types navigated through a process's space.
    pub fn types_in(&self, dtb: Dtb) -> Types<'_> {
        Types { obj: self, dtb }
    }
}

/// A `WinObject`'s struct/type namespace bound to a read address space: the
/// entry point for layout lookups and fluent cursors. Cheap to copy. To structs
/// what the object itself is to symbols.
#[derive(Clone, Copy)]
pub struct Types<'a> {
    obj: &'a WinObject,
    dtb: Dtb,
}

impl<'a> Types<'a> {
    /// The parsed layout of struct `name` from the object's PDB (cached).
    pub fn layout<S>(self, name: S) -> Result<Arc<TypeInfo>>
    where
        S: Into<String> + AsRef<str>,
    {
        let guid = self.obj.guid.ok_or(Error::ExpectedSymbols)?;
        self.obj
            .symbols
            .dump_struct_with_types(guid, name.as_ref())
            .ok_or_else(|| Error::StructNotFound(name.into()))
    }

    /// Open a struct cursor at `base` in this space. The layout `name` resolves
    /// against the object's PDB; reads come from this space's `dtb`.
    pub fn struct_at(self, name: &str, base: VirtAddr) -> Result<StructRef<'a>> {
        let ti = self.layout(name)?;
        Ok(StructRef {
            obj: self.obj,
            dtb: self.dtb,
            ti,
            base,
            image: None,
        })
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
        let (obj, dtb) = (self.obj, self.dtb);
        let record_ti = self.layout(record_type)?;
        let link_offset = record_ti.field_offset(link_field)?;

        let list_memory = |dtb: Dtb| obj.address_space(&obj.phys, dtb);

        let mut current: VirtAddr = list_memory(dtb).read(head)?;
        const MAX: usize = 1000;
        // Bounded, and a corrupt list that loops through any number of nodes
        // (not only back onto itself) ends at the first link seen twice.
        let mut seen = std::collections::HashSet::with_capacity(16);

        Ok(std::iter::from_fn(move || {
            if current.is_zero() || current == head || seen.len() >= MAX || !seen.insert(current.0)
            {
                return None;
            }

            let record = StructRef {
                obj,
                dtb,
                ti: Arc::clone(&record_ti),
                base: VirtAddr(current.0.wrapping_sub(link_offset)),
                image: None,
            }
            .prefetch();

            // Flink sits at offset 0 of the link's _LIST_ENTRY
            match record.read_field_at::<VirtAddr>(link_offset) {
                Ok(next) => current = next,
                Err(e) => {
                    current = head;
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
    obj: &'a WinObject,
    dtb: Dtb,
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
        self.obj.address_space(&self.obj.phys, self.dtb)
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
        StructRef {
            obj: self.obj,
            dtb: self.dtb,
            ti,
            base,
            image: None,
        }
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
        let target: VirtAddr = self.read_field_at(field.offset as u64)?;
        let ti = self.obj.types().layout(&struct_name)?;
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
        let ti = self.obj.types().layout(&type_name)?;
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
        let buffer: VirtAddr = self.read_field("Buffer")?;
        if length == 0 || buffer.is_zero() {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; length as usize];
        self.memory().read_bytes(buffer, &mut buf)?;
        let u16s: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
        self.obj
            .types_in(self.dtb)
            .list_at(head, record_type, link_field)
    }
}

/// Read a loader-table record (`_LDR_DATA_TABLE_ENTRY` / `_KLDR_DATA_TABLE_ENTRY`)
/// into a `ModuleInfo`, or `None` when it has no base address (skip it). Shared
/// by the process- and kernel-module walks, which differ only in their list.
fn module_info_from_record(record: &StructRef<'_>) -> Result<Option<ModuleInfo>> {
    let dll_base: VirtAddr = record.read_field("DllBase")?;
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
    if let Ok(entry_point) = record.read_field::<VirtAddr>("EntryPoint")
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

pub struct Guest {
    pub ntoskrnl: WinObject,
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
        let start = unique_process_id_offset
            .min(dir_table_base_offset)
            .min(active_process_links_offset)
            .min(image_file_name_offset);
        let end = (unique_process_id_offset + 8)
            .max(dir_table_base_offset + 8)
            .max(active_process_links_offset + 8)
            .max(image_file_name_offset + IMAGE_FILE_NAME_LEN as u64);
        Ok(Self {
            start,
            bytes: vec![0u8; (end - start) as usize],
            unique_process_id_offset,
            dir_table_base_offset,
            active_process_links_offset,
            image_file_name_offset,
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
        && header.chunks_exact(8).any(|c| c == b"POOLCODE")
}

fn is_ntoskrnl_pte(phys: &PhysMem, pte: PageTableEntry) -> Result<bool> {
    if pte.is_user() || !pte.is_nx() {
        return Ok(false);
    }

    let Ok(header) = phys.read::<[u8; 0x1000]>(pte.page_frame()) else {
        return Ok(false);
    };
    Ok(is_ntoskrnl_header(&header))
}

fn find_ntoskrnl_va(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
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

        let pdpte_count = if pml4_index == pml4e_count - 1 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (pdpt_index, pdpte) in pdpt.into_iter().take(pdpte_count).enumerate() {
            if !pdpte.is_present() {
                continue;
            }

            if pdpte.is_large_page() {
                if let Ok(true) = is_ntoskrnl_pte(phys, pdpte) {
                    return Ok(Some(VirtAddr::construct(pml4_index, pdpt_index, 0, 0)));
                }

                continue;
            }

            let Ok(pd) = phys.read::<[PageTableEntry; 512]>(pdpte.page_frame()) else {
                continue;
            };

            let pde_count = if pdpt_index == pdpte_count - 1 {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (pd_index, pde) in pd.into_iter().take(pde_count).enumerate() {
                if !pde.is_present() {
                    continue;
                }

                if pde.is_large_page() {
                    if let Ok(true) = is_ntoskrnl_pte(phys, pde) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, pdpt_index, pd_index, 0,
                        )));
                    }

                    continue;
                }

                let Ok(pt) = phys.read::<[PageTableEntry; 512]>(pde.page_frame()) else {
                    continue;
                };

                let pte_count = if pd_index == pde_count - 1 {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (pt_index, pte) in pt.into_iter().take(pte_count).enumerate() {
                    if !pte.is_present() {
                        continue;
                    }

                    if let Ok(true) = is_ntoskrnl_pte(phys, pte) {
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
                let block = l1.arm64_page_frame();
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
                    let block = l2.arm64_page_frame();
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

fn find_ntoskrnl(phys: Arc<PhysMem>, symbols: Arc<SymbolStore>) -> Result<Option<WinObject>> {
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

    Ok(Some(WinObject::new_with_arch(
        phys,
        symbols,
        kernel_dtb,
        ntoskrnl_va,
        arch,
    )))
}

impl Guest {
    pub fn from_kernel(ntoskrnl: WinObject) -> Self {
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
        slot: impl Fn(&mut HaltMemo) -> &mut Option<Vec<T>>,
        walk: impl FnOnce() -> Result<Vec<T>>,
    ) -> Result<Vec<T>> {
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

    fn queue_module_symbol_load(
        symbols: &SymbolStore,
        downloads: &mut Vec<ModuleSymbolLoad>,
        ready: &mut Vec<ModuleSymbolLoad>,
        load: ModuleSymbolLoad,
    ) {
        if symbols.has_matching_pdb(&load.job) {
            ready.push(load);
        } else {
            downloads.push(load);
        }
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
        let ntoskrnl = if let Some(kernel_base) = kernel_base_hint {
            let (kernel_dtb, arch) = find_kernel(&phys)?.ok_or(Error::NtoskrnlNotFound)?;
            WinObject::new_with_arch(phys, symbols, kernel_dtb, kernel_base, arch)
        } else {
            find_ntoskrnl(phys, symbols)?.ok_or(Error::NtoskrnlNotFound)?
        }
        .load_symbols()?;

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
            .and_then(|info| info.system_info.as_ref())
            .and_then(|si| Arch::from_machine_type(si.machine_image_type as u16))
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

        let obj = WinObject::new_with_arch(
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
            Err(_) if is_triage => {
                let driver = phys
                    .dmp_info()
                    .and_then(|info| info.triage_drivers.iter().find(|d| d.base == ntoskrnl_va.0))
                    .cloned()
                    .ok_or(Error::NtoskrnlNotFound)?;

                WinObject::new_with_arch(phys, symbols, kernel_dtb, ntoskrnl_va, arch)
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
        })
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

    pub fn winobj_from_process_info(&self, info: &ProcessInfo) -> Result<WinObject> {
        let eprocess = self
            .ntoskrnl
            .types_in(info.dtb)
            .struct_at("_EPROCESS", info.eprocess_va)?;

        let peb = eprocess.follow("Peb")?;
        if peb.addr().is_zero() {
            return Err(Error::MissingPEB);
        }

        let base_address: VirtAddr = peb.read_field("ImageBaseAddress")?;
        Ok(self.ntoskrnl.sibling(info.dtb, base_address))
    }

    pub fn process_modules(&self, info: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
        let eprocess = self
            .ntoskrnl
            .types_in(info.dtb)
            .struct_at("_EPROCESS", info.eprocess_va)?;

        let peb = eprocess.follow("Peb")?;
        if peb.addr().is_zero() {
            return Err(Error::MissingPEB);
        }

        let ldr = peb.follow("Ldr")?;
        if ldr.addr().is_zero() {
            // process still initializing: no loaded-module list yet
            return Ok(Vec::new());
        }

        let mut modules = Vec::new();
        for record in ldr.list(
            "InLoadOrderModuleList",
            "_LDR_DATA_TABLE_ENTRY",
            "InLoadOrderLinks",
        )? {
            if let Some(module) = module_info_from_record(&record?)? {
                modules.push(module);
            }
        }

        Ok(modules)
    }

    pub fn kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        self.memoized(
            |memo| &mut memo.kernel_modules,
            || self.walk_kernel_modules(),
        )
    }

    fn walk_kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        let head = self.ntoskrnl.symbol("PsLoadedModuleList")?.address();

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
        let process_mem = self.ntoskrnl.sibling(info.dtb, VirtAddr(0));
        let memory = process_mem.memory();
        populate_module_versions(modules, &memory);
    }

    fn is_session_space(addr: VirtAddr) -> bool {
        let prefix = addr.0 >> 44;
        prefix == 0xFFFF8 || prefix == 0xFFFF9 || prefix == 0xFFFFA
    }

    pub fn load_module_symbols(
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        skip_session_space: bool,
        arch: Arch,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut report = ModuleSymbolLoadReport::new(modules.len());
        let mut jobs_with_info: Vec<ModuleSymbolLoad> = Vec::new();
        let mut image_jobs: Vec<(DownloadJob, ModuleInfo)> = Vec::new();
        let mut ready_to_load: Vec<ModuleSymbolLoad> = Vec::new();

        for module in modules {
            if skip_session_space && Self::is_session_space(module.base_address) {
                Self::apply_module_symbol_status(
                    symbols,
                    &mut report,
                    dtb,
                    &module,
                    ModuleSymbolStatus::Skipped,
                );
                continue;
            }

            match symbols.extract_download_job(phys, dtb, &module, arch) {
                Ok(ModuleSymbolDiscovery::Ready { job, guid, source }) => {
                    Self::queue_module_symbol_load(
                        symbols,
                        &mut jobs_with_info,
                        &mut ready_to_load,
                        ModuleSymbolLoad::new(job, guid, source, module, dtb),
                    );
                }
                Ok(ModuleSymbolDiscovery::NeedsImage { image_job }) => {
                    image_jobs.push((image_job, module));
                }
                Err(_e) if module.time_date_stamp.is_some() => {
                    let tds = module.time_date_stamp.unwrap();
                    match SymbolStore::build_image_download_job(&module.name, tds, module.size) {
                        Ok(image_job) => image_jobs.push((image_job, module)),
                        Err(e) => Self::apply_module_symbol_status(
                            symbols,
                            &mut report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        ),
                    }
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        &mut report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        let image_results =
            download_jobs_parallel(image_jobs.iter().map(|(job, _)| job.clone()).collect());

        for ((image_job, module), result) in image_jobs.into_iter().zip(image_results) {
            match result {
                Ok(_) => match symbols.extract_download_job_from_image_file(&image_job.path) {
                    Ok(Some((job, guid))) => {
                        Self::queue_module_symbol_load(
                            symbols,
                            &mut jobs_with_info,
                            &mut ready_to_load,
                            ModuleSymbolLoad::new(
                                job,
                                guid,
                                ModuleSymbolSource::Image,
                                module,
                                dtb,
                            ),
                        );
                    }
                    Ok(None) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            &mut report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::MissingDebugInfo,
                        );
                    }
                    Err(e) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            &mut report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                },
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        &mut report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        let download_results =
            download_jobs_parallel(jobs_with_info.iter().map(|load| load.job.clone()).collect());

        // Modules whose remembered PDB no longer resolves: forget the record
        // and rediscover them from the target below.
        let mut stale_identities: Vec<ModuleInfo> = Vec::new();
        for (load, result) in jobs_with_info.into_iter().zip(download_results) {
            match result {
                Ok(_) => ready_to_load.push(load),
                Err(_) if matches!(load.source, ModuleSymbolSource::Identity) => {
                    stale_identities.push(load.module);
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        &mut report,
                        dtb,
                        &load.module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        if !ready_to_load.is_empty() {
            let pb = ProgressBar::new(ready_to_load.len() as u64);
            pb.set_style(
                ProgressStyle::with_template("Indexing [{bar:40}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("#-"),
            );

            let results = ready_to_load
                .into_par_iter()
                .map(|load| {
                    let result = symbols.load_downloaded_pdb(&load);
                    pb.inc(1);
                    (load, result)
                })
                .collect::<Vec<_>>();

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
                            &mut report,
                            dtb,
                            &load.module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                }
            }
        }

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

#[cfg(test)]
mod tests {
    use super::{
        IMAGE_BLOCK, ModuleSymbolLoadReport, PE_HEADER_PROBE, PeImage, read_pe_header_page,
        read_pe_image,
    };
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::memory::{AddressSpace, DTB_IDENTITY};
    use crate::symbols::SymbolIndexDiagnostic;
    use crate::types::{PhysAddr, VirtAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
