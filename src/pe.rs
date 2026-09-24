//! PE image access independent of any guest: the demand-read [`PeImage`],
//! header and section reads, the export directory, version resources, and
//! mapping an on-disk image file to its in-memory layout.

use crate::{
    backend::MemoryOps,
    bytes::{get_u16, get_u32, read_u16, read_u32},
    error::{Error, Result},
    memory::{self, PAGE_SIZE},
    types::*,
};
use pelite::{PeFile, PeView, Wrap, image::IMAGE_DIRECTORY_ENTRY_EXPORT};
use std::borrow::Cow;
use std::collections::{HashMap, hash_map::Entry};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// One export recovered from a module's mapped PE export directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleExportInfo {
    pub name: Option<String>,
    pub ordinal: u32,
    pub address: Option<VirtAddr>,
    pub forwarder: Option<String>,
}

/// A module image addressed by RVA. An on-disk image is complete; an image
/// read from guest memory is demand-read in `IMAGE_BLOCK`-sized blocks and
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
    let e_lfanew = read_u32(probe, 0x3c) as usize;
    let nt = probe.get(e_lfanew..e_lfanew.checked_add(24)?)?;
    if &nt[..4] != b"PE\0\0" {
        return Some(probe.len());
    }
    let sections = read_u16(nt, 6) as usize;
    let optional = read_u16(nt, 20) as usize;
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
    let u32_at = |offset| read_u32(&data, offset);
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
        let name_rva = read_u32(&names, index * 4);
        let function_index = usize::from(read_u16(&ordinals, index * 2));
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
        let function_rva = read_u32(&functions, index * 4);
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

    let ver_rva = get_u32(&rsrc_buf, data_entry_rva)?;
    let ver_size = get_u32(&rsrc_buf, data_entry_rva + 4)? as usize;
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
    let rva = get_u32(rsrc, data_entry_off)?;
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
    let num_named = get_u16(rsrc, dir_off + 12)? as usize;
    let num_id = get_u16(rsrc, dir_off + 14)? as usize;
    let entries_start = dir_off + 16;
    for i in num_named..(num_named + num_id) {
        let entry_off = entries_start + i * 8;
        let id = get_u32(rsrc, entry_off)?;
        if id == target_id {
            return get_u32(rsrc, entry_off + 4);
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
    let num_named = get_u16(rsrc, dir_off + 12)? as usize;
    let num_id = get_u16(rsrc, dir_off + 14)? as usize;
    if num_named + num_id == 0 {
        return None;
    }
    let first_entry_off = dir_off + 16;
    get_u32(rsrc, first_entry_off + 4)
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
    let file_minor = read_u16(info, 8);
    let file_major = read_u16(info, 10);
    let file_revision = read_u16(info, 12);
    let file_build = read_u16(info, 14);

    let prod_minor = read_u16(info, 16);
    let prod_major = read_u16(info, 18);
    let prod_revision = read_u16(info, 20);
    let prod_build = read_u16(info, 22);

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

#[cfg(test)]
mod tests {
    use super::{
        IMAGE_BLOCK, ModuleExportInfo, PE_HEADER_PROBE, PeImage, read_pe_exports,
        read_pe_header_page, read_pe_image,
    };
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::memory::{AddressSpace, DTB_IDENTITY};
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
}
