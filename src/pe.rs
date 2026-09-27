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
use pelite::{
    PeFile, PeView, Wrap,
    image::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG},
};
use std::borrow::Cow;
use std::collections::{HashMap, hash_map::Entry};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

pub mod headers;

/// A module's header page. `PeView` rejects bytes that are not 4-byte
/// aligned, and a bare byte array has no alignment of its own, so a header
/// page returned by value parsed or failed depending on where the compiler
/// happened to place it.
#[repr(C, align(8))]
pub struct HeaderPage([u8; PAGE_SIZE]);

impl HeaderPage {
    pub fn zeroed() -> Self {
        Self([0; PAGE_SIZE])
    }
}

impl Deref for HeaderPage {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HeaderPage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for HeaderPage {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

/// `IMAGE_EXPORT_DIRECTORY` and the DLL name it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub version: (u16, u16),
    pub name: String,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// A mapped image's export directory and the exports it lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageExports {
    /// `None` when the image exports nothing.
    pub directory: Option<ExportDirectory>,
    pub exports: Vec<ModuleExportInfo>,
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
    headers: Box<HeaderPage>,
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
            ImageBody::Lazy(lazy) => &lazy.headers[..],
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

    /// The image's [`CodeLayout`]. Its metadata pointer is relocated to the
    /// header's `ImageBase`, which the loader rewrites to where it mapped the
    /// image, so an in-memory image and its file both resolve it.
    pub fn code_layout(&self) -> Option<CodeLayout> {
        let base = image_base(&PeView::from_bytes(self.headers()).ok()?);
        read_code_layout(base, &|rva, buf| {
            let bytes = usize::try_from(rva)
                .ok()
                .and_then(|rva| self.read(rva, buf.len()))
                .ok_or(Error::BadVirtualAddress(VirtAddr(base.wrapping_add(rva))))?;
            buf.copy_from_slice(&bytes);
            Ok(())
        })
        .ok()
        .flatten()
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
) -> Result<HeaderPage> {
    read_pe_header_page_with(&|address, buf| memory.read_bytes(base_address + address, buf))
}

/// [`read_pe_header_page`] over a reader addressed by RVA.
fn read_pe_header_page_with(read: &dyn Fn(u64, &mut [u8]) -> Result<()>) -> Result<HeaderPage> {
    let mut header_buf = HeaderPage::zeroed();
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

const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
/// `CHPEMetadataPointer` in `IMAGE_LOAD_CONFIG_DIRECTORY64`: a virtual
/// address, relocated like the image.
const LOAD_CONFIG_CHPE_METADATA: usize = 0xc8;
/// The same pointer in `IMAGE_LOAD_CONFIG_DIRECTORY32`, 4 bytes wide.
const LOAD_CONFIG32_CHPE_METADATA: usize = 0x7c;
/// More range entries than any image has; bounds a corrupt count.
const MAX_CODE_RANGES: u32 = 1 << 16;
/// `IMAGE_ARM64EC_METADATA` through `ExtraRFETable` (+0x40) and
/// `ExtraRFETableSize` (+0x44).
const ARM64EC_METADATA_EXTRA_RFE: usize = 0x40;
const ARM64EC_METADATA_SIZE: usize = 0x48;

/// Which instruction set each part of an image holds: the header's machine,
/// and for a hybrid image, the code-range map in its load config. An ARM64X
/// or ARM64EC image's map (`IMAGE_ARM64EC_METADATA`) types each range ARM64,
/// ARM64EC, or AMD64; an ARM64EC image's header says AMD64 though most of its
/// code is ARM64. A CHPE x86 image (`IMAGE_CHPE_METADATA_X86`, the x86 system
/// DLLs of ARM64 Windows) marks the ranges compiled to native ARM64 code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeLayout {
    machine: CodeMachine,
    /// `(start RVA, end RVA, machine)`, sorted by start.
    ranges: Vec<(u32, u32, CodeMachine)>,
    /// An ARM64EC or ARM64X image's second runtime-function table
    /// (`ExtraRFETable`), for the code the header's machine does not
    /// describe; see [`Self::runtime_functions`].
    extra_runtime_functions: Option<(u32, u32)>,
}

impl CodeLayout {
    /// The machine the image's header names.
    pub fn machine(&self) -> CodeMachine {
        self.machine
    }

    pub fn machine_at(&self, rva: u32) -> CodeMachine {
        let index = self.ranges.partition_point(|&(start, _, _)| start <= rva);
        index
            .checked_sub(1)
            .map(|index| self.ranges[index])
            .filter(|&(_, end, _)| rva < end)
            .map_or(self.machine, |(_, _, machine)| machine)
    }

    /// The RVA and size of the runtime functions (`.pdata`) for code of
    /// `machine`, given the image's `exception` directory. A hybrid image
    /// has one table per instruction set: the exception directory holds the
    /// header machine's, `ExtraRFETable` the other's. An ARM64X image loaded
    /// into an x64 process has its header rewritten to AMD64 and the two
    /// swapped, so which is which follows the header, not the file.
    pub fn runtime_functions(
        &self,
        machine: CodeMachine,
        exception: Option<(u32, u32)>,
    ) -> Option<(u32, u32)> {
        if machine == self.machine {
            exception
        } else {
            self.extra_runtime_functions
        }
    }
}

/// Read an image's [`CodeLayout`] through `read`, which reads at an RVA of
/// the image mapped at `base`. `None` when the header names no machine this
/// debugger decodes.
pub fn read_code_layout(
    base: u64,
    read: &dyn Fn(u64, &mut [u8]) -> Result<()>,
) -> Result<Option<CodeLayout>> {
    let headers = read_pe_header_page_with(read)?;
    let view = PeView::from_bytes(&*headers)?;
    let machine = match view.file_header().Machine {
        IMAGE_FILE_MACHINE_I386 => CodeMachine::X86,
        IMAGE_FILE_MACHINE_AMD64 => CodeMachine::Amd64,
        IMAGE_FILE_MACHINE_ARM64 => CodeMachine::Arm64,
        _ => return Ok(None),
    };
    let mut layout = CodeLayout {
        machine,
        ranges: Vec::new(),
        extra_runtime_functions: None,
    };
    let (field, width) = match view.optional_header() {
        Wrap::T64(_) => (LOAD_CONFIG_CHPE_METADATA, 8),
        Wrap::T32(_) => (LOAD_CONFIG32_CHPE_METADATA, 4),
    };
    let config = view
        .data_directory()
        .get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .copied();
    let Some(config) = config.filter(|config| config.VirtualAddress != 0) else {
        return Ok(Some(layout));
    };
    let mut size = [0u8; 4];
    read(u64::from(config.VirtualAddress), &mut size)?;
    if (u32::from_le_bytes(size) as usize) < field + width {
        return Ok(Some(layout));
    }
    let mut pointer = [0u8; 8];
    read(
        u64::from(config.VirtualAddress) + field as u64,
        &mut pointer[..width],
    )?;
    let metadata = u64::from_le_bytes(pointer);
    let Some(metadata_rva) = metadata.checked_sub(base).filter(|_| metadata != 0) else {
        return Ok(Some(layout));
    };
    // A CHPE x86 image's metadata has the map and nothing this reads after
    // it; an ARM64EC image's goes on to its second runtime-function table.
    let mut header = [0u8; ARM64EC_METADATA_SIZE];
    let header_len = if machine == CodeMachine::X86 {
        12
    } else {
        ARM64EC_METADATA_SIZE
    };
    read(metadata_rva, &mut header[..header_len])?;
    if machine != CodeMachine::X86 {
        let table = read_u32(&header, ARM64EC_METADATA_EXTRA_RFE);
        let size = read_u32(&header, ARM64EC_METADATA_EXTRA_RFE + 4);
        layout.extra_runtime_functions = (table != 0 && size != 0).then_some((table, size));
    }
    let (map_rva, count) = (read_u32(&header, 4), read_u32(&header, 8));
    if count == 0 || count > MAX_CODE_RANGES {
        return Ok(Some(layout));
    }
    let mut entries = vec![0u8; count as usize * 8];
    read(u64::from(map_rva), &mut entries)?;
    layout.ranges = entries
        .as_chunks::<8>()
        .0
        .iter()
        .filter_map(|entry| {
            let (offset, length) = (read_u32(entry, 0), read_u32(entry, 4));
            let (start, machine) = if machine == CodeMachine::X86 {
                // Bit 0 marks native code; the rest of the offset is the start.
                let native = offset & 1 != 0;
                (
                    offset & !1,
                    if native {
                        CodeMachine::Arm64
                    } else {
                        CodeMachine::X86
                    },
                )
            } else {
                // The low two bits type the range: ARM64, ARM64EC, or AMD64.
                let machine = match offset & 3 {
                    0 | 1 => CodeMachine::Arm64,
                    2 => CodeMachine::Amd64,
                    _ => return None,
                };
                (offset & !3, machine)
            };
            Some((start, start.saturating_add(length), machine))
        })
        .collect();
    layout.ranges.sort_unstable_by_key(|&(start, _, _)| start);
    Ok(Some(layout))
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

/// `len` bytes at `rva` of `image`, or an error naming `what` was being read
/// there.
fn read_image_bytes<'a>(
    image: &'a PeImage,
    rva: u32,
    len: usize,
    what: &str,
) -> Result<Cow<'a, [u8]>> {
    let start = rva as usize;
    if start.checked_add(len).is_none_or(|end| end > image.size) {
        return Err(Error::DebugInfo(format!(
            "{what} at RVA {rva:#x} ({len:#x} bytes) lies outside SizeOfImage"
        )));
    }
    image.read(start, len).ok_or_else(|| {
        Error::DebugInfo(format!(
            "{what} at RVA {rva:#x} ({len:#x} bytes) is not resident"
        ))
    })
}

/// The NUL-terminated string at `rva` of `image`, up to 4096 bytes, shown
/// lossily when not UTF-8. It is read in pieces that stop at each block end,
/// so a string that ends just before a paged-out block still reads.
fn read_image_c_string(image: &PeImage, rva: u32, what: &str) -> Result<String> {
    const CHUNK: usize = 128;
    const MAX_LENGTH: usize = 4096;
    let mut bytes = Vec::new();
    let mut at = rva as usize;
    while bytes.len() < MAX_LENGTH {
        let len = CHUNK
            .min(IMAGE_BLOCK - at % IMAGE_BLOCK)
            .min(MAX_LENGTH - bytes.len())
            .min(image.size.saturating_sub(at));
        if len == 0 {
            break;
        }
        let chunk = image
            .read(at, len)
            .ok_or_else(|| Error::DebugInfo(format!("{what} at RVA {rva:#x} is not resident")))?;
        if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk);
        at += len;
    }
    Err(Error::DebugInfo(format!(
        "{what} at RVA {rva:#x} is unterminated or longer than {MAX_LENGTH} bytes"
    )))
}

/// Read the export directory and its named and ordinal-only exports from a
/// mapped module image. The image remains lazy: only the export directory,
/// address tables, and strings are fetched. A directory entry with a zero
/// RVA or size (most drivers') means the image exports nothing.
pub fn read_pe_exports(image: &PeImage, base: VirtAddr) -> Result<ImageExports> {
    const DIRECTORY_SIZE: usize = 40;
    const MAX_EXPORTS: usize = 1_000_000;

    let headers = PeView::from_bytes(image.headers())?;
    let Some(entry) = headers
        .data_directory()
        .get(IMAGE_DIRECTORY_ENTRY_EXPORT)
        .filter(|entry| entry.VirtualAddress != 0 && entry.Size != 0)
    else {
        return Ok(ImageExports {
            directory: None,
            exports: Vec::new(),
        });
    };
    let directory_rva = entry.VirtualAddress;
    let directory_size = entry.Size;
    if directory_size < DIRECTORY_SIZE as u32 {
        return Err(Error::DebugInfo(format!(
            "export directory size {directory_size:#x} is shorter than \
             IMAGE_EXPORT_DIRECTORY ({DIRECTORY_SIZE:#x})"
        )));
    }
    let data = read_image_bytes(image, directory_rva, DIRECTORY_SIZE, "export directory")?;
    let u32_at = |offset| read_u32(&data, offset);
    let directory = ExportDirectory {
        characteristics: u32_at(0),
        time_date_stamp: u32_at(4),
        version: (read_u16(&data, 8), read_u16(&data, 10)),
        name: read_image_c_string(image, u32_at(12), "export DLL name")?,
        ordinal_base: u32_at(16),
        number_of_functions: u32_at(20),
        number_of_names: u32_at(24),
        address_of_functions: u32_at(28),
        address_of_names: u32_at(32),
        address_of_name_ordinals: u32_at(36),
    };
    let ordinal_base = directory.ordinal_base;
    let function_count = directory.number_of_functions as usize;
    let name_count = directory.number_of_names as usize;
    if function_count > MAX_EXPORTS || name_count > MAX_EXPORTS {
        return Err(Error::DebugInfo(
            "PE export count exceeds the safety bound".into(),
        ));
    }

    let functions = read_image_bytes(
        image,
        directory.address_of_functions,
        function_count * 4,
        "export address table",
    )?;
    let names = read_image_bytes(
        image,
        directory.address_of_names,
        name_count * 4,
        "export name table",
    )?;
    let ordinals = read_image_bytes(
        image,
        directory.address_of_name_ordinals,
        name_count * 2,
        "export ordinal table",
    )?;
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
            .push(read_image_c_string(image, name_rva, "export name")?);
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
            .then(|| read_image_c_string(image, function_rva, "export forwarder"))
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
    Ok(ImageExports {
        directory: Some(directory),
        exports,
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
        IMAGE_BLOCK, ModuleExportInfo, PE_HEADER_PROBE, PeImage, read_code_layout,
        read_image_c_string, read_pe_exports, read_pe_header_page, read_pe_image,
    };
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::memory::{AddressSpace, DTB_IDENTITY};
    use crate::types::CodeMachine;
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

    /// [`synthetic_image`] as a hybrid image of `machine` loaded at `base`: a
    /// load config in `.rdata` whose `CHPEMetadataPointer` (relocated, as in
    /// memory) leads to a code map of `ranges` (`StartOffset`, `Length`).
    fn hybrid_image(machine: u16, base: u64, ranges: &[(u32, u32)]) -> Vec<u8> {
        let mut image = synthetic_image();
        let (pe, config, metadata, map) = (0x80, 0x2000usize, 0x2100usize, 0x2200usize);
        image[pe + 4..pe + 6].copy_from_slice(&machine.to_le_bytes());
        let directory = pe + 24 + 112 + 10 * 8;
        image[directory..directory + 4].copy_from_slice(&(config as u32).to_le_bytes());
        image[directory + 4..directory + 8].copy_from_slice(&0x140u32.to_le_bytes());
        image[config..config + 0x140].fill(0);
        image[config..config + 4].copy_from_slice(&0x140u32.to_le_bytes());
        image[config + 0xc8..config + 0xd0]
            .copy_from_slice(&(base + metadata as u64).to_le_bytes());
        image[metadata..metadata + 12].fill(0);
        image[metadata..metadata + 4].copy_from_slice(&1u32.to_le_bytes());
        image[metadata + 4..metadata + 8].copy_from_slice(&(map as u32).to_le_bytes());
        image[metadata + 8..metadata + 12].copy_from_slice(&(ranges.len() as u32).to_le_bytes());
        for (index, (offset, length)) in ranges.iter().enumerate() {
            let entry = map + 8 * index;
            image[entry..entry + 4].copy_from_slice(&offset.to_le_bytes());
            image[entry + 4..entry + 8].copy_from_slice(&length.to_le_bytes());
        }
        image
    }

    /// A PE32 x86 image at `base` whose CHPE map marks 0x1000..0x1100 native
    /// and 0x1100..0x1200 x86. The 32-bit optional header keeps its data
    /// directories at +96 and the load config's CHPEMetadataPointer at 0x7c.
    fn chpe_x86_image(base: u32) -> Vec<u8> {
        let mut image = vec![0u8; 0x3000];
        let mut put = |at: usize, bytes: &[u8]| image[at..at + bytes.len()].copy_from_slice(bytes);
        let pe = 0x80;
        put(0, b"MZ");
        put(0x3c, &(pe as u32).to_le_bytes());
        put(pe, b"PE\0\0");
        put(pe + 4, &0x14cu16.to_le_bytes());
        put(pe + 6, &1u16.to_le_bytes());
        put(pe + 20, &224u16.to_le_bytes());
        let opt = pe + 24;
        put(opt, &0x10bu16.to_le_bytes());
        put(opt + 28, &base.to_le_bytes());
        put(opt + 32, &0x1000u32.to_le_bytes());
        put(opt + 36, &0x200u32.to_le_bytes());
        put(opt + 56, &0x3000u32.to_le_bytes());
        put(opt + 60, &0x1000u32.to_le_bytes());
        put(opt + 92, &16u32.to_le_bytes());
        put(opt + 96 + 10 * 8, &0x2000u32.to_le_bytes());
        put(opt + 96 + 10 * 8 + 4, &0x80u32.to_le_bytes());
        let section = opt + 224;
        put(section, b".text\0\0\0");
        put(section + 8, &0x2000u32.to_le_bytes());
        put(section + 12, &0x1000u32.to_le_bytes());
        put(section + 16, &0x2000u32.to_le_bytes());
        put(section + 20, &0x1000u32.to_le_bytes());
        put(0x2000, &0x80u32.to_le_bytes());
        put(0x2000 + 0x7c, &(base + 0x2100).to_le_bytes());
        put(0x2104, &0x2200u32.to_le_bytes());
        put(0x2108, &2u32.to_le_bytes());
        put(0x2200, &(0x1000u32 | 1).to_le_bytes());
        put(0x2204, &0x100u32.to_le_bytes());
        put(0x2208, &0x1100u32.to_le_bytes());
        put(0x220c, &0x100u32.to_le_bytes());
        image
    }

    fn layout_of(image: &[u8], base: u64) -> super::CodeLayout {
        let read = |rva: u64, buf: &mut [u8]| {
            let start = rva as usize;
            buf.copy_from_slice(&image[start..start + buf.len()]);
            Ok(())
        };
        read_code_layout(base, &read).unwrap().unwrap()
    }

    /// A hybrid image keeps each instruction set's runtime functions in its
    /// own table: the exception directory is the header machine's and
    /// `ExtraRFETable` the other's. An ARM64X image loaded into an x64
    /// process has its header rewritten to AMD64 and the two swapped; reading
    /// the file's assignment there sends every lookup to the wrong format.
    #[test]
    fn a_hybrid_image_names_each_machines_runtime_functions_by_its_header() {
        const BASE: u64 = 0x7ff6_0000_0000;
        let (exception, extra): ((u32, u32), (u32, u32)) = ((0x2800, 0x60), (0x2900, 0x30));
        for (header, own, other) in [
            (0xaa64u16, CodeMachine::Arm64, CodeMachine::Amd64),
            (0x8664, CodeMachine::Amd64, CodeMachine::Arm64),
        ] {
            let mut image = hybrid_image(header, BASE, &[(0x1000 | 2, 0x100)]);
            image[0x2140..0x2144].copy_from_slice(&extra.0.to_le_bytes());
            image[0x2144..0x2148].copy_from_slice(&extra.1.to_le_bytes());
            let layout = layout_of(&image, BASE);
            assert_eq!(
                layout.runtime_functions(own, Some(exception)),
                Some(exception)
            );
            assert_eq!(
                layout.runtime_functions(other, Some(exception)),
                Some(extra)
            );
        }
    }

    /// An ARM64EC image says AMD64 in its header while most of its code is
    /// ARM64; its code map types each range (ARM64, ARM64EC, AMD64), and
    /// only an AMD64 range is x64 code.
    #[test]
    fn a_hybrid_image_code_map_decides_each_range() {
        const BASE: u64 = 0x7ff6_0000_0000;
        let image = hybrid_image(0x8664, BASE, &[(0x1000 | 1, 0x800), (0x1800 | 2, 0x800)]);
        let layout = layout_of(&image, BASE);
        assert_eq!(layout.machine_at(0x1000), CodeMachine::Arm64);
        assert_eq!(layout.machine_at(0x17fc), CodeMachine::Arm64);
        assert_eq!(layout.machine_at(0x1800), CodeMachine::Amd64);
        // Outside the map, the header's machine.
        assert_eq!(layout.machine_at(0x2400), CodeMachine::Amd64);

        let arm64x = hybrid_image(0xaa64, BASE, &[(0x1000 | 2, 0x100)]);
        let layout = layout_of(&arm64x, BASE);
        assert_eq!(layout.machine_at(0x1080), CodeMachine::Amd64);
        assert_eq!(layout.machine_at(0x1100), CodeMachine::Arm64);

        // A CHPE x86 image: bit 0 of an entry marks native ARM64 code.
        let layout = layout_of(&chpe_x86_image(0x70_0000), 0x70_0000);
        assert_eq!(layout.machine_at(0x1080), CodeMachine::Arm64);
        assert_eq!(layout.machine_at(0x1180), CodeMachine::X86);
        assert_eq!(layout.machine_at(0x2400), CodeMachine::X86);

        // No metadata: the header decides everywhere.
        let mut plain = synthetic_image();
        plain[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert_eq!(
            layout_of(&plain, BASE).machine_at(0x1000),
            CodeMachine::Arm64
        );
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

    /// A string that ends just before a paged-out block reads, though a
    /// fixed-size read from its start would run into that block.
    #[test]
    fn an_image_string_ending_before_an_unreadable_block_reads() {
        let mut bytes = synthetic_image();
        bytes[0x1ff0..0x1ff6].copy_from_slice(b"Alpha\0");
        let memory = Arc::new(ImageMemory::new(0x10_0000, bytes));
        memory.readable.store(0x2000, Ordering::Relaxed);
        let image = open_image(&memory);
        assert_eq!(
            read_image_c_string(&image, 0x1ff0, "name").unwrap(),
            "Alpha"
        );
        // One that runs on into the unreadable block does not.
        assert!(read_image_c_string(&image, 0x1ff8, "name").is_err());
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
        let exports = read_pe_exports(&PeImage::complete(image), VirtAddr(0x10_0000)).unwrap();
        assert_eq!(exports.directory, None);
        assert_eq!(exports.exports, []);
    }

    #[test]
    fn exports_cover_named_forwarded_and_ordinal_only_entries() {
        let base = VirtAddr(0x10_0000);
        let exports = read_pe_exports(&PeImage::complete(image_with_exports(1)), base).unwrap();
        assert_eq!(
            exports.exports,
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
