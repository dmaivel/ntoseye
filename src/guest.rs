use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    memory::{self, AddressSpace, DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::{
        DownloadJob, FieldInfo, ModuleSymbolDiscovery, ModuleSymbolLoad, ModuleSymbolSource,
        ModuleSymbolStatus, ParsedType, SymbolStore, TypeInfo, download_jobs_parallel,
    },
    types::*,
};
use indicatif::{ProgressBar, ProgressStyle};
use pelite::pe64::{Pe, PeFile, PeView};
use rayon::prelude::*;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use zerocopy::{FromBytes, IntoBytes};

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

#[derive(Debug, Clone, Default)]
pub struct ModuleSymbolLoadReport {
    pub total: usize,
    pub loaded: usize,
    pub no_pdb: usize,
    pub skipped: usize,
    pub failed: usize,
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

    pub fn failed_count(&self) -> usize {
        self.failed
    }
}

/// A module image reconstructed from guest memory. Sections whose pages were
/// paged out are zero-filled in `bytes`; their RVA ranges are recorded as `holes`
/// so callers don't mistake a zeroed region for real data (which previously led
/// to e.g. fabricated unwind frames or a wrong PDB GUID).
#[derive(Debug)]
pub struct PeImage {
    bytes: Vec<u8>,
    holes: Vec<Range<usize>>,
}

impl PeImage {
    /// Wrap fully-available bytes (e.g. a complete on-disk image) with no holes.
    pub fn complete(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            holes: Vec::new(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the image has no paged-out holes (e.g. built from an on-disk
    /// file). Used to avoid re-fetching an already-complete image.
    pub fn is_complete(&self) -> bool {
        self.holes.is_empty()
    }

    /// Whether `[at, at+len)` is fully backed by real guest data: in bounds and
    /// not overlapping a paged-out hole.
    pub fn is_present(&self, at: usize, len: usize) -> bool {
        let Some(end) = at.checked_add(len) else {
            return false;
        };
        end <= self.bytes.len() && !self.holes.iter().any(|h| at < h.end && h.start < end)
    }

    /// Slice of `len` bytes at offset `at`, but only if fully present (see
    /// [`is_present`](Self::is_present)); otherwise None.
    pub fn present_slice(&self, at: usize, len: usize) -> Option<&[u8]> {
        self.is_present(at, len).then(|| &self.bytes[at..at + len])
    }
}

pub fn read_pe_image<'a, B: MemoryOps<PhysAddr>>(
    base_address: VirtAddr,
    memory: &memory::AddressSpace<'a, B>,
) -> Result<PeImage> {
    let mut header_buf = [0u8; 0x1000];

    memory.read_bytes(base_address, &mut header_buf)?;

    let view = PeView::from_bytes(&header_buf)?;
    let optional_header = view.optional_header();
    let sections = view.section_headers();

    let total_size = optional_header.SizeOfImage as usize;
    let mut image_buffer = vec![0u8; total_size];
    let mut holes: Vec<Range<usize>> = Vec::new();

    let header_len = std::cmp::min(header_buf.len(), total_size);
    image_buffer[..header_len].copy_from_slice(&header_buf[..header_len]);

    for section in sections {
        let v_addr = section.VirtualAddress as usize;
        let v_size = section.VirtualSize as usize;
        let raw_size = section.SizeOfRawData as usize;
        let copy_size = std::cmp::max(v_size, raw_size);

        if copy_size == 0 || v_addr + copy_size > total_size {
            continue;
        }

        let target_slice = &mut image_buffer[v_addr..v_addr + copy_size];
        match memory.read_bytes(VirtAddr(base_address.0 + v_addr as u64), target_slice) {
            Ok(()) => {}
            // a page in the section is paged out: read_bytes fills up to the hole
            // and leaves the rest zeroed. Record the unread tail so callers know
            // not to trust those bytes.
            Err(Error::PartialRead(read)) => holes.push((v_addr + read)..(v_addr + copy_size)),
            // the section's first page is unmapped: the whole region is unread
            Err(_) => holes.push(v_addr..(v_addr + copy_size)),
        }
    }

    Ok(PeImage {
        bytes: image_buffer,
        holes,
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
    let mut header_buf = [0u8; 0x1000];
    memory.read_bytes(base, &mut header_buf).ok()?;
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

    let mut header_buf = [0u8; 0x1000];
    memory.read_bytes(base, &mut header_buf).ok()?;
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

/// A structured view into a loaded module's memory: it carries its own address
/// space (`dtb`) and the handles needed to read and resolve symbols/types
/// (`kvm`, `symbols`), so navigation methods don't take them as arguments. The
/// handles are shared (`Arc`), not borrowed; a `WinObject` can't borrow its
/// `Target` siblings, but it can own a refcounted handle to them.
pub struct WinObject {
    pub base_address: VirtAddr,
    dtb: Dtb,
    binary_snapshot: Vec<u8>,
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
        Self {
            base_address,
            dtb,
            binary_snapshot: Vec::new(),
            guid: None,
            phys,
            symbols,
        }
    }

    pub fn load_symbols(mut self) -> Result<Self> {
        // Clone the Arc handles to a local so `load_from_binary` can take
        // `&mut self` without aliasing the `self.symbols`/`self.phys` fields.
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

    /// Size of the cached binary snapshot (0 until [`view`](Self::view) has run).
    pub fn binary_size(&self) -> usize {
        self.binary_snapshot.len()
    }

    /// A sibling object sharing this one's `kvm`/`symbols` handles, at a new
    /// base in a possibly different address space. Symbols aren't loaded yet
    /// (`guid` is `None`); call [`load_symbols`](Self::load_symbols) to attach.
    pub fn sibling(&self, dtb: Dtb, base_address: VirtAddr) -> WinObject {
        WinObject::new(
            Arc::clone(&self.phys),
            Arc::clone(&self.symbols),
            dtb,
            base_address,
        )
    }

    pub fn address_of(&self, rva: impl Into<u64>) -> VirtAddr {
        self.base_address + rva.into()
    }

    pub fn memory(&self) -> memory::AddressSpace<'_, Arc<PhysMem>> {
        memory::AddressSpace::new(&self.phys, self.dtb)
    }

    pub fn symbol<S>(&self, name: S) -> Result<SymbolRef<'_>>
    where
        S: Into<String>,
    {
        let name = name.into();

        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let rva = self
            .symbols
            .symbol_rva(guid, &name)
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

    // TODO binary should probably be reread to ensure correctness
    // TODO bc shared memory might/isnt used, this needs to be mutable to ensure data is fresh :/
    pub fn view(&mut self) -> Option<PeView<'_>> {
        if self.binary_snapshot.is_empty() {
            // Clone the Arc so the read borrow doesn't alias `&mut self`.
            let phys = Arc::clone(&self.phys);
            let memory = AddressSpace::new(&phys, self.dtb);
            self.binary_snapshot = read_pe_image(self.base_address, &memory).ok()?.bytes;
        }

        PeView::from_bytes(&self.binary_snapshot).ok()
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
    pub fn layout<S>(self, name: S) -> Result<TypeInfo>
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
        })
    }

    /// Walk an intrusive `_LIST_ENTRY` starting at a bare head address (e.g. a
    /// list-head symbol like `PsLoadedModuleList`), yielding a cursor per
    /// record. `record_type`/`link_field` give the record layout and the
    /// embedded link (`CONTAINING_RECORD`). Iteration is bounded and stops on a
    /// cycle. Shared by [`StructRef::list`], which sources `head` from a field.
    pub fn list_at(
        self,
        head: VirtAddr,
        record_type: &str,
        link_field: &str,
    ) -> Result<impl Iterator<Item = Result<StructRef<'a>>> + 'a> {
        let (obj, dtb) = (self.obj, self.dtb);
        let record_ti = self.layout(record_type)?;
        let link_offset = record_ti.field_offset(link_field)?;

        let mut current: VirtAddr = AddressSpace::new(&obj.phys, dtb).read(head)?;
        let mut count = 0usize;
        const MAX: usize = 1000;

        Ok(std::iter::from_fn(move || {
            if current.is_zero() || current == head || count >= MAX {
                return None;
            }
            count += 1;

            let record = StructRef {
                obj,
                dtb,
                ti: record_ti.clone(),
                base: current - link_offset,
            };

            // Flink sits at offset 0 of the link's _LIST_ENTRY
            match AddressSpace::new(&obj.phys, dtb).read::<VirtAddr>(current) {
                Ok(next) if next == current => current = head, // self-loop: stop after this
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
    ti: TypeInfo,
    base: VirtAddr,
}

impl<'a> StructRef<'a> {
    fn memory(&self) -> AddressSpace<'a, Arc<PhysMem>> {
        AddressSpace::new(&self.obj.phys, self.dtb)
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
    fn with(&self, ti: TypeInfo, base: VirtAddr) -> StructRef<'a> {
        StructRef {
            obj: self.obj,
            dtb: self.dtb,
            ti,
            base,
        }
    }

    /// Read a scalar field by name. The Rust type `T` (inferred from context)
    /// fixes the read width; the PDB only supplies the offset.
    pub fn read_field<T: Copy + zerocopy::FromZeros + FromBytes + IntoBytes>(
        &self,
        name: &str,
    ) -> Result<T> {
        let offset = self.field(name)?.offset as u64;
        self.memory().read(self.base + offset)
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
        let target: VirtAddr = self.memory().read(self.base + field.offset as u64)?;
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
        Ok(self.with(ti, base))
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
}

fn is_valid_kernel_dtb(phys: &PhysMem, dtb: Dtb) -> Result<bool> {
    let kernel_pml4 = phys.read::<[PageTableEntry; 256]>(dtb + 8 * 256)?;

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

fn find_kernel_dtb(phys: &PhysMem) -> Result<Option<Dtb>> {
    for dtb in (0x1000..0x1000000).step_by(PAGE_SIZE) {
        if is_valid_kernel_dtb(phys, dtb)? {
            return Ok(Some(dtb));
        }
    }

    Ok(None)
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

    let header = phys.read::<[u8; 0x1000]>(pte.page_frame())?;
    Ok(is_ntoskrnl_header(&header))
}

fn find_ntoskrnl_va(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xfffff80800000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let kernel_pml4 = phys.read::<[PageTableEntry; 256]>(kernel_dtb + 8 * 256)?;
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
        let pdpt = phys.read::<[PageTableEntry; 512]>(pml4e.page_frame())?;

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
                // Unlikely but just making sure
                if let Ok(true) = is_ntoskrnl_pte(phys, pdpte) {
                    return Ok(Some(VirtAddr::construct(pml4_index, pdpt_index, 0, 0)));
                }

                continue;
            }

            let pd = phys.read::<[PageTableEntry; 512]>(pdpte.page_frame())?;

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

                let pt = phys.read::<[PageTableEntry; 512]>(pde.page_frame())?;

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

/// Scan captured virtual memory regions for the ntoskrnl PE header.
///
/// Triage dumps have no page tables, so we can't walk the PML4. Instead we
/// probe the identity-mapped virtual memory for the MZ header + POOLCODE
/// marker, the same heuristic `is_ntoskrnl_pte` uses but at the virtual
/// layer.
fn find_ntoskrnl_va_triage(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    let space = AddressSpace::new(phys, kernel_dtb);

    // Triage dumps include ntoskrnl's base in PsLoadedModuleList. We can
    // read the PsLoadedModuleList VA from the header; the list entry itself
    // is at nt!PsLoadedModuleList, which is inside ntoskrnl. The first
    // entry in the list is ntoskrnl's own LDR_DATA_TABLE_ENTRY whose
    // DllBase field gives us the base.
    //
    // But we don't have the offsets yet (no PDB). Instead, just try
    // addresses from the data blocks that look like kernel-space PE headers.
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
    let Some(kernel_dtb) = find_kernel_dtb(&phys)? else {
        return Ok(None);
    };

    let Some(ntoskrnl_va) = find_ntoskrnl_va(kernel_dtb, &phys)? else {
        return Ok(None);
    };

    Ok(Some(WinObject::new(phys, symbols, kernel_dtb, ntoskrnl_va)))
}

impl Guest {
    fn queue_module_symbol_load(
        symbols: &SymbolStore,
        downloads: &mut Vec<ModuleSymbolLoad>,
        ready: &mut Vec<ModuleSymbolLoad>,
        load: ModuleSymbolLoad,
    ) {
        if symbols.has_guid(load.guid) {
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
            let kernel_dtb = find_kernel_dtb(&phys)?.ok_or(Error::NtoskrnlNotFound)?;
            WinObject::new(phys, symbols, kernel_dtb, kernel_base)
        } else {
            find_ntoskrnl(phys, symbols)?.ok_or(Error::NtoskrnlNotFound)?
        }
        .load_symbols()?;

        // Type/enum layout lookups prefer the kernel's definitions over
        // same-named user-mode types once attached to a process; tell the
        // symbol store which guid is the kernel's.
        ntoskrnl.register_as_kernel();

        Ok(Self { ntoskrnl })
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

        let ntoskrnl_va = if is_triage {
            find_ntoskrnl_va_triage(kernel_dtb, &phys)?
        } else {
            find_ntoskrnl_va(kernel_dtb, &phys)?
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

        let obj = WinObject::new(
            Arc::clone(&phys),
            Arc::clone(&symbols),
            kernel_dtb,
            ntoskrnl_va,
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

                WinObject::new(phys, symbols, kernel_dtb, ntoskrnl_va)
                    .load_symbols_from_module_info(
                        &driver.name,
                        driver.time_date_stamp,
                        driver.size,
                    )?
            }
            Err(e) => return Err(e),
        };

        ntoskrnl.register_as_kernel();
        Ok(Self { ntoskrnl })
    }

    pub fn enumerate_processes(&self) -> Result<Vec<ProcessInfo>> {
        let memory = self.ntoskrnl.memory();

        let eprocess_info = self.ntoskrnl.types().layout("_EPROCESS")?;
        let active_process_links_offset = eprocess_info.field_offset("ActiveProcessLinks")?;
        let pcb_offset = eprocess_info.field_offset("Pcb")?;

        let kprocess_info = self.ntoskrnl.types().layout("_KPROCESS")?;
        let dir_table_base_offset =
            pcb_offset + kprocess_info.field_offset("DirectoryTableBase")?;
        let unique_process_id_offset = eprocess_info.field_offset("UniqueProcessId")?;
        let image_filename_offset = eprocess_info.field_offset("ImageFileName")?;

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

        loop {
            if current_eprocess.0 == 0 || visited.contains(&current_eprocess.0) {
                break;
            }
            visited.insert(current_eprocess.0);

            let pid = memory.read::<u64>(current_eprocess + unique_process_id_offset)?;
            let dtb = memory.read::<Dtb>(current_eprocess + dir_table_base_offset)? & !0xfff;

            if dtb == 0 {
                break;
            }

            let name = self
                .full_process_name(current_eprocess, dtb)
                .unwrap_or_else(|_| {
                    let mut name_buf = [0u8; 15];
                    if memory
                        .read_bytes(current_eprocess + image_filename_offset, &mut name_buf)
                        .is_ok()
                    {
                        String::from_utf8_lossy(
                            &name_buf[..name_buf.iter().position(|&c| c == 0).unwrap_or(15)],
                        )
                        .to_string()
                    } else {
                        "<unknown>".to_string()
                    }
                });

            processes.push(ProcessInfo {
                pid,
                name,
                dtb,
                eprocess_va: current_eprocess,
            });

            let flink = memory.read::<VirtAddr>(current_eprocess + active_process_links_offset)?;
            if flink.0 == 0 || Some(flink) == ps_active_process_head {
                break;
            }

            current_eprocess = flink - active_process_links_offset;
            if current_eprocess == ps_initial_system_process {
                break;
            }
        }

        Ok(processes)
    }

    /// Short (15-char) image name straight from EPROCESS.ImageFileName: a
    /// single read, unlike enumerate_processes or the PEB walk
    pub fn process_image_name(&self, eprocess_va: VirtAddr) -> Option<String> {
        let memory = self.ntoskrnl.memory();
        let offset = self
            .ntoskrnl
            .types()
            .layout("_EPROCESS")
            .ok()?
            .field_offset("ImageFileName")
            .ok()?;
        let mut name_buf = [0u8; 15];
        memory
            .read_bytes(eprocess_va + offset, &mut name_buf)
            .ok()?;
        let len = name_buf.iter().position(|&c| c == 0).unwrap_or(15);
        if len == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&name_buf[..len]).to_string())
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

    pub fn populate_process_module_versions(
        &self,
        modules: &mut [ModuleInfo],
        info: &ProcessInfo,
    ) {
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

            match SymbolStore::extract_download_job(phys, dtb, &module.name, module.base_address) {
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
                Ok(_) => match SymbolStore::extract_download_job_from_image_file(&image_job.path) {
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

        for (load, result) in jobs_with_info.into_iter().zip(download_results) {
            match result {
                Ok(_) => ready_to_load.push(load),
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
                    let module = load.module.clone();
                    let result = symbols.load_downloaded_pdb(&load);
                    pb.inc(1);
                    (module, result)
                })
                .collect::<Vec<_>>();

            pb.finish_and_clear();

            for (module, result) in results {
                match result {
                    Ok(_) => {
                        report.record_status(&ModuleSymbolStatus::Loaded);
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
        Self::load_module_symbols(phys, symbols, modules, dtb, true)
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

        symbols.retain_modules_for_dtb(dtb, &modules);
        let missing = modules
            .into_iter()
            .filter(|module| {
                symbols
                    .module_symbol_status(dtb, module.base_address)
                    .is_none()
            })
            .collect::<Vec<_>>();

        Self::load_module_symbols(phys, symbols, missing, dtb, true)
    }

    pub fn load_all_process_module_symbols(
        &self,
        phys: &PhysMem,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<ModuleSymbolLoadReport> {
        let modules = self.process_modules(info)?;
        let dtb = info.dtb;
        Self::load_module_symbols(phys, symbols, modules, dtb, false)
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
        Self::load_module_symbols(phys, symbols, modules, dtb, false)
    }
}

#[cfg(test)]
mod tests {
    use super::PeImage;

    #[test]
    fn pe_image_present_respects_holes_and_bounds() {
        // 0x100 bytes with one paged-out hole at [0x40, 0x80)
        let hole = 0x40..0x80;
        let image = PeImage {
            bytes: vec![0u8; 0x100],
            holes: vec![hole],
        };

        // fully outside the hole -> present
        assert!(image.is_present(0x00, 0x40));
        assert!(image.is_present(0x80, 0x80));
        assert!(image.present_slice(0x10, 0x10).is_some());

        // any overlap with the hole -> absent (including straddling either edge)
        assert!(!image.is_present(0x40, 0x01));
        assert!(!image.is_present(0x3f, 0x02));
        assert!(!image.is_present(0x7f, 0x02));
        assert!(image.present_slice(0x38, 0x10).is_none());

        // out of bounds -> absent, and overflow doesn't panic
        assert!(!image.is_present(0xf0, 0x20));
        assert!(!image.is_present(usize::MAX, 1));
    }
}
