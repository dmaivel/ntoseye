use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{ModuleInfo, WinObject},
    memory,
    types::{Dtb, PhysAddr, VirtAddr},
};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use pdb2::{FallibleIterator, PrimitiveKind, TypeData, TypeFinder, TypeIndex};
use pelite::{
    image::{
        GUID, IMAGE_DEBUG_CV_INFO_PDB70, IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DIRECTORY_ENTRY_DEBUG,
    },
    pe64::{Pe, PeFile, PeView, debug::CodeView},
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use spin::Mutex;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use std::{fmt, io::Cursor};

// NOTE global is probably fine here?
pub static FORCE_DOWNLOADS: OnceLock<bool> = OnceLock::new();

pub static PDB_SERVERS: OnceLock<Vec<String>> = OnceLock::new();

const DEFAULT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

fn pdb_servers() -> &'static [String] {
    static RESOLVED: OnceLock<Vec<String>> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        let mut servers = PDB_SERVERS.get().cloned().unwrap_or_default();
        if let Ok(env_val) = std::env::var("NTOSEYE_PDB_SERVERS") {
            servers.extend(
                env_val
                    .split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from),
            );
        }
        servers.push(DEFAULT_SYMBOL_SERVER.to_string());
        servers
    })
}

#[derive(Default, Clone)]
pub struct SymbolIndex {
    /// Symbol/type names, sorted and deduped. Matched fuzzily by `search`
    names: Vec<String>,
}

pub struct SymbolStore {
    pdbs: DashMap<u128, Mutex<pdb2::PDB<'static, Cursor<&'static [u8]>>>>,

    mmaps: DashMap<u128, Arc<Mmap>>,
    index: DashMap<u128, SymbolIndex>,
    index_types: DashMap<u128, SymbolIndex>,
    index_enums: DashMap<u128, SymbolIndex>,
    /// guid -> (public symbol name -> RVA). Built alongside `index` so symbol
    /// address resolution is an O(1) lookup instead of a per-call PDB scan
    symbol_rvas: DashMap<u128, HashMap<String, u32>>,

    /// (guid, struct name) -> parsed layout. `dump_struct_with_types`
    /// otherwise rescans the entire PDB type stream on every call; keying on
    /// guid makes this self-coherent (a reloaded module gets a new guid, so a
    /// stale entry can never be returned).
    type_cache: DashMap<(u128, String), Arc<TypeInfo>>,

    modules: DashMap<(Dtb, u64), LoadedModule>,
    module_status: DashMap<(Dtb, u64), ModuleSymbolStatus>,
    module_source: DashMap<(Dtb, u64), ModuleSymbolSource>,

    /// GUID of the kernel (`ntoskrnl`) module. Type/enum *layout* lookups are
    /// address-space independent, so they must always prefer the kernel's
    /// definitions over same-named user-mode types (e.g. ntdll's `_KPRCB`) and
    /// over kernel-only types the attached process simply omits. Resolution
    /// consults this guid first regardless of the attached DTB; updated whenever
    /// the kernel module (re)loads.
    kernel_guid: Mutex<Option<u128>>,
}

fn guid_to_u128(guid: GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.Data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.Data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.Data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.Data4);
    u128::from_be_bytes(bytes)
}

pub fn format_symbol_with_offset(module: &str, name: &str, offset: u32) -> String {
    if offset == 0 {
        format!("{module}!{name}")
    } else {
        format!("{module}!{name}+{offset:#x}")
    }
}

static HOME_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static HOME_MIGRATION: OnceLock<Option<(PathBuf, PathBuf)>> = OnceLock::new();

pub fn ntoseye_home() -> Option<PathBuf> {
    HOME_PATH.get_or_init(resolve_ntoseye_home).clone()
}

pub fn home_migration() -> Option<(PathBuf, PathBuf)> {
    let _ = ntoseye_home();
    HOME_MIGRATION.get().and_then(|migration| migration.clone())
}

fn resolve_ntoseye_home() -> Option<PathBuf> {
    let user_home = user_home_dir()?;
    let path = user_home.join(".ntoseye");
    let legacy = user_home.join(".config").join("ntoseye");
    let migration = migrate_legacy_home(&legacy, &path).ok()?;
    let _ = HOME_MIGRATION.set(migration);
    std::fs::create_dir_all(&path).ok()?;
    Some(path)
}

fn migrate_legacy_home(legacy: &Path, home: &Path) -> std::io::Result<Option<(PathBuf, PathBuf)>> {
    if legacy.is_dir() && !home.exists() {
        std::fs::rename(legacy, home)?;
        return Ok(Some((legacy.to_path_buf(), home.to_path_buf())));
    }
    Ok(None)
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .map(|user| PathBuf::from(format!("/home/{user}")))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

fn symbols_directory() -> Option<PathBuf> {
    let symbols_path = ntoseye_home()?.join("symbols");
    std::fs::create_dir_all(&symbols_path).ok()?;
    Some(symbols_path)
}

fn images_directory() -> Option<PathBuf> {
    let images_path = ntoseye_home()?.join("images");
    std::fs::create_dir_all(&images_path).ok()?;
    Some(images_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ntoseye-{name}-{nonce}"))
    }

    #[test]
    fn migrate_legacy_home_moves_directory() {
        let root = temp_root("home-migrate");
        let legacy = root.join(".config").join("ntoseye");
        let home = root.join(".ntoseye");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("aliases"), "alias ubp bp ${1}; g\n").unwrap();

        let migration = migrate_legacy_home(&legacy, &home).unwrap();

        assert!(migration.is_some());
        assert!(!legacy.exists());
        assert!(home.join("aliases").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migrate_legacy_home_does_not_merge_when_new_home_exists() {
        let root = temp_root("home-existing");
        let legacy = root.join(".config").join("ntoseye");
        let home = root.join(".ntoseye");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let migration = migrate_legacy_home(&legacy, &home).unwrap();

        assert!(migration.is_none());
        assert!(legacy.exists());
        assert!(home.exists());

        let _ = std::fs::remove_dir_all(root);
    }
}

/// Information needed to download a PDB file
#[derive(Debug, Clone)]
pub struct DownloadJob {
    pub urls: Vec<String>,
    pub path: PathBuf,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolStatus {
    Loaded,
    MissingDebugInfo,
    Skipped,
    Failed(#[allow(dead_code)] String),
}

impl ModuleSymbolStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::MissingDebugInfo => "no-pdb",
            Self::Skipped => "skipped",
            Self::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolSource {
    Memory,
    Image,
}

impl ModuleSymbolSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Image => "image",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolDiscovery {
    Ready {
        job: DownloadJob,
        guid: u128,
        source: ModuleSymbolSource,
    },
    NeedsImage {
        image_job: DownloadJob,
    },
}

#[derive(Debug, Clone)]
pub struct ModuleSymbolLoad {
    pub job: DownloadJob,
    pub guid: u128,
    pub source: ModuleSymbolSource,
    pub module: ModuleInfo,
    pub dtb: Dtb,
}

impl ModuleSymbolLoad {
    pub fn new(
        job: DownloadJob,
        guid: u128,
        source: ModuleSymbolSource,
        module: ModuleInfo,
        dtb: Dtb,
    ) -> Self {
        Self {
            job,
            guid,
            source,
            module,
            dtb,
        }
    }

    fn loaded_module(&self) -> LoadedModule {
        LoadedModule {
            name: self.module.name.clone(),
            guid: self.guid,
            base_address: self.module.base_address,
            size: self.module.size,
            dtb: self.dtb,
        }
    }
}

impl DownloadJob {
    pub fn needs_download(&self) -> bool {
        !self.path.exists() || *FORCE_DOWNLOADS.get_or_init(|| false)
    }
}

fn format_progress_name(name: &str) -> String {
    const WIDTH: usize = 32;
    format!("{name:<WIDTH$}")
}

const DOWNLOAD_PROGRESS_TEMPLATE: &str = "{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})";
const TASK_PROGRESS_TEMPLATE: &str = "{msg} [{bar:40}] {pos}/{len}";

fn download_progress_style() -> Result<ProgressStyle> {
    Ok(ProgressStyle::with_template(DOWNLOAD_PROGRESS_TEMPLATE)?.progress_chars("#-"))
}

fn task_progress_style() -> ProgressStyle {
    ProgressStyle::with_template(TASK_PROGRESS_TEMPLATE)
        .unwrap()
        .progress_chars("#-")
}

fn download_job(job: &DownloadJob, pb: ProgressBar) -> Result<()> {
    if !job.needs_download() {
        return Ok(());
    }

    let mut last_err = None;
    for url in &job.urls {
        match reqwest::blocking::get(url).and_then(|r| r.error_for_status()) {
            Ok(response) => {
                return download_response(job, response, pb);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("DownloadJob.urls must not be empty").into())
}

fn download_response(
    job: &DownloadJob,
    response: reqwest::blocking::Response,
    pb: ProgressBar,
) -> Result<()> {
    let total_size = response.content_length().unwrap_or(0);

    pb.set_style(download_progress_style()?);
    pb.set_length(total_size);
    pb.set_message(format_progress_name(&job.filename));

    if let Some(parent) = job.path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Download to a unique temp file and rename into place. Writing the final
    // path directly truncates it in place, which corrupts the file under
    // concurrent duplicate jobs and rips pages out from under any existing
    // mmap of it (--force-download-symbols re-downloads loaded PDBs); a rename
    // leaves prior mappings on the old inode intact.
    static DOWNLOAD_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp_path = job.path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        DOWNLOAD_SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let mut file = File::create(&tmp_path)?;
    let mut downloaded = pb.wrap_read(response);

    let copied = std::io::copy(&mut downloaded, &mut file);
    drop(file);
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    std::fs::rename(&tmp_path, &job.path)?;
    pb.finish_and_clear();

    Ok(())
}

pub fn download_jobs_parallel(jobs: Vec<DownloadJob>) -> Vec<Result<PathBuf>> {
    let mp = Arc::new(MultiProgress::new());

    jobs.into_par_iter()
        .map(|job| {
            if !job.needs_download() {
                return Ok(job.path);
            }

            let mp = Arc::clone(&mp);
            download_job(&job, mp.add(ProgressBar::new(0))).map(|_| job.path)
        })
        .collect::<Vec<_>>()
}

#[derive(Debug, Clone)]
pub enum ParsedType {
    Primitive(String),
    Struct(String),
    Union(String),
    Enum(String),
    Pointer(Box<ParsedType>),
    Array(Box<ParsedType>, u32),
    Bitfield {
        underlying: Box<ParsedType>,
        pos: u8,
        len: u8,
    },
    Function(Box<ParsedType>, Vec<ParsedType>),
    Unknown,
}

impl ParsedType {
    /// The element count when this is a fixed array of single-byte char-like
    /// primitives, i.e. an inline C string buffer such as
    /// `_EPROCESS.ImageFileName` (`UCHAR[15]`). `None` for anything else. Lets a
    /// host auto-decode such fields to text instead of handing back raw bytes.
    pub fn c_string_len(&self) -> Option<u32> {
        match self {
            ParsedType::Array(inner, count) => match inner.as_ref() {
                ParsedType::Primitive(name) if matches!(name.as_str(), "CHAR" | "UCHAR") => {
                    Some(*count)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for ParsedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedType::Primitive(s)
            | ParsedType::Struct(s)
            | ParsedType::Union(s)
            | ParsedType::Enum(s) => write!(f, "{}", s),
            // ParsedType::Pointer(inner) => write!(f, "{}*", inner),
            ParsedType::Pointer(inner) => {
                if let ParsedType::Function(ret_type, args) = &**inner {
                    write!(f, "{} (*)(", ret_type)?;
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", arg)?;
                    }
                    write!(f, ")")
                } else {
                    write!(f, "{}*", inner)
                }
            }
            ParsedType::Array(inner, count) => write!(f, "{}[{}]", inner, count),
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => write!(f, "{} : {} @ bit {}", underlying, len, pos),
            ParsedType::Function(ret_type, args) => {
                write!(f, "{} (", ret_type)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            ParsedType::Unknown => write!(f, "<?>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub offset: u32,
    #[allow(dead_code)]
    pub size: u64,
    pub type_data: ParsedType,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub fields: HashMap<String, FieldInfo>,
}

impl TypeInfo {
    pub fn field_offset<S>(&self, field_name: S) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        self.fields
            .get(field_name.as_ref())
            .ok_or(Error::FieldNotFound(field_name.into()))
            .map(|f| f.offset as u64)
    }

    /// Decode the scalar leaves of this struct out of a buffer covering the whole
    /// type, returning `(field, value)` pairs sorted by offset. The field-decoding
    /// rules shared by the pyo3 and MCP struct readers; each host packs the neutral
    /// [`FieldValue`] into its own form. Nested struct/union fields (reported by
    /// the PDB with size 0) and fields running past the buffer are skipped; read
    /// those separately with their own type.
    pub fn decode_fields(&self, buf: &[u8]) -> Vec<(String, FieldValue)> {
        let mut out: Vec<(u32, String, FieldValue)> = Vec::new();
        for (name, f) in self.fields.iter() {
            let off = f.offset as usize;
            let sz = f.size as usize;
            if sz == 0 || off + sz > buf.len() {
                continue;
            }
            let slice = &buf[off..off + sz];
            let value = match &f.type_data {
                ParsedType::Bitfield { pos, len, .. } => {
                    let raw = le_uint(slice);
                    let mask = if *len >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << len) - 1
                    };
                    FieldValue::Bitfield((raw >> pos) & mask)
                }
                ParsedType::Pointer(_) => FieldValue::Pointer(le_uint(slice)),
                _ => match sz {
                    1 | 2 | 4 | 8 => FieldValue::Int(le_uint(slice)),
                    _ => FieldValue::Bytes(slice.to_vec()),
                },
            };
            out.push((f.offset, name.clone(), value));
        }
        out.sort_by_key(|(off, _, _)| *off);
        out.into_iter()
            .map(|(_, name, value)| (name, value))
            .collect()
    }
}

/// A decoded scalar field leaf, the neutral result of [`TypeInfo::decode_fields`].
/// Hosts render this into their own representation (Python objects / JSON).
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// A 1/2/4/8-byte integer.
    Int(u64),
    /// A pointer-sized address (semantically distinct so hosts can render it as
    /// hex if they prefer).
    Pointer(u64),
    /// A bitfield already masked/shifted to its value.
    Bitfield(u64),
    /// A larger aggregate (array, embedded blob) returned verbatim.
    Bytes(Vec<u8>),
}

/// Little-endian unsigned integer from up to 8 bytes, shared by the
/// struct/bitfield decoders.
pub fn le_uint(slice: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in slice.iter().take(8).enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

/// A loaded module with its symbols and address range.
/// Used to track modules across both kernel and user address spaces.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub guid: u128,
    pub base_address: VirtAddr,
    pub size: u32,
    pub dtb: Dtb,
}

impl LoadedModule {
    fn end_address(&self) -> VirtAddr {
        VirtAddr(self.base_address.0.saturating_add(self.size as u64))
    }

    fn contains_address(&self, address: VirtAddr) -> bool {
        address.0 >= self.base_address.0 && address.0 < self.end_address().0
    }
}

impl Default for SymbolStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolStore {
    fn module_key(dtb: Dtb, base_address: VirtAddr) -> (Dtb, u64) {
        (dtb, base_address.0)
    }

    pub fn new() -> Self {
        Self {
            pdbs: DashMap::new(),
            mmaps: DashMap::new(),
            index: DashMap::new(),
            index_types: DashMap::new(),
            index_enums: DashMap::new(),
            symbol_rvas: DashMap::new(),
            type_cache: DashMap::new(),
            modules: DashMap::new(),
            module_status: DashMap::new(),
            module_source: DashMap::new(),
            kernel_guid: Mutex::new(None),
        }
    }

    /// Record the kernel module's guid so type/enum layout lookups can prefer it
    /// regardless of the attached address space. Called when `ntoskrnl` loads.
    pub fn set_kernel_guid(&self, guid: Option<u128>) {
        *self.kernel_guid.lock() = guid;
    }

    pub fn kernel_guid(&self) -> Option<u128> {
        *self.kernel_guid.lock()
    }

    pub fn clear_modules_for_dtb(&self, dtb: Dtb) {
        let module_keys: Vec<_> = self
            .modules
            .iter()
            .filter_map(|module| (module.dtb == dtb).then_some(*module.key()))
            .collect();
        for key in module_keys {
            self.modules.remove(&key);
        }

        let status_keys: Vec<_> = self
            .module_status
            .iter()
            .filter_map(|status| (status.key().0 == dtb).then_some(*status.key()))
            .collect();
        for key in status_keys {
            self.module_status.remove(&key);
        }

        let source_keys: Vec<_> = self
            .module_source
            .iter()
            .filter_map(|source| (source.key().0 == dtb).then_some(*source.key()))
            .collect();
        for key in source_keys {
            self.module_source.remove(&key);
        }
    }

    pub fn retain_modules_for_dtb(&self, dtb: Dtb, live_modules: &[ModuleInfo]) {
        let live_bases = live_modules
            .iter()
            .map(|module| module.base_address.0)
            .collect::<HashSet<_>>();

        let module_keys: Vec<_> = self
            .modules
            .iter()
            .filter_map(|module| {
                (module.dtb == dtb && !live_bases.contains(&module.base_address.0))
                    .then_some(*module.key())
            })
            .collect();
        for key in module_keys {
            self.modules.remove(&key);
        }

        let status_keys: Vec<_> = self
            .module_status
            .iter()
            .filter_map(|status| {
                let (status_dtb, base) = *status.key();
                (status_dtb == dtb && !live_bases.contains(&base)).then_some(*status.key())
            })
            .collect();
        for key in status_keys {
            self.module_status.remove(&key);
        }

        let source_keys: Vec<_> = self
            .module_source
            .iter()
            .filter_map(|source| {
                let (source_dtb, base) = *source.key();
                (source_dtb == dtb && !live_bases.contains(&base)).then_some(*source.key())
            })
            .collect();
        for key in source_keys {
            self.module_source.remove(&key);
        }
    }

    pub fn set_module_symbol_status(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
        status: ModuleSymbolStatus,
    ) {
        let key = Self::module_key(dtb, base_address);
        if !matches!(status, ModuleSymbolStatus::Loaded) {
            self.module_source.remove(&key);
        }
        self.module_status.insert(key, status);
    }

    pub fn module_symbol_status(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Option<ModuleSymbolStatus> {
        self.module_status
            .get(&Self::module_key(dtb, base_address))
            .map(|status| status.clone())
    }

    pub fn set_module_symbol_source(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
        source: ModuleSymbolSource,
    ) {
        self.module_source
            .insert(Self::module_key(dtb, base_address), source);
    }

    pub fn module_symbol_source(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Option<ModuleSymbolSource> {
        self.module_source
            .get(&Self::module_key(dtb, base_address))
            .map(|source| source.clone())
    }

    fn read_debug_directory_location<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(u32, u32)>> {
        let mut header_buf = [0u8; 0x1000];
        memory.read_bytes(base_address, &mut header_buf)?;
        let view = PeView::from_bytes(&header_buf)?;
        Ok(view
            .data_directory()
            .get(IMAGE_DIRECTORY_ENTRY_DEBUG)
            .map(|entry| (entry.VirtualAddress, entry.Size)))
    }

    fn read_debug_directory_entries<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        debug_rva: u32,
        debug_size: u32,
    ) -> Result<Vec<IMAGE_DEBUG_DIRECTORY>> {
        if debug_size == 0 {
            return Ok(Vec::new());
        }

        let entry_size = size_of::<IMAGE_DEBUG_DIRECTORY>();
        if !(debug_size as usize).is_multiple_of(entry_size) {
            return Err(Error::DebugInfo(format!(
                "debug directory size {:#x} is not a multiple of {}",
                debug_size, entry_size
            )));
        }

        let mut bytes = vec![0u8; debug_size as usize];
        memory.read_bytes(base_address + debug_rva as u64, &mut bytes)?;

        let mut entries = Vec::new();
        for chunk in bytes.chunks_exact(entry_size) {
            let entry =
                unsafe { ptr::read_unaligned(chunk.as_ptr() as *const IMAGE_DEBUG_DIRECTORY) };
            entries.push(entry);
        }

        Ok(entries)
    }

    fn read_codeview_from_memory<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        entry: &IMAGE_DEBUG_DIRECTORY,
    ) -> Result<(String, Option<(DownloadJob, u128)>)> {
        if entry.AddressOfRawData == 0 || entry.SizeOfData < 4 {
            return Err(Error::DebugInfo(
                "codeview entry is missing raw data".to_string(),
            ));
        }

        let mut bytes = vec![0u8; entry.SizeOfData as usize];
        memory.read_bytes(base_address + entry.AddressOfRawData as u64, &mut bytes)?;
        let signature = bytes
            .get(..4)
            .ok_or_else(|| Error::DebugInfo("codeview entry truncated".to_string()))?;

        match signature {
            b"RSDS" => {
                if bytes.len() < size_of::<IMAGE_DEBUG_CV_INFO_PDB70>() {
                    return Err(Error::DebugInfo("RSDS entry truncated".to_string()));
                }

                let image = unsafe {
                    ptr::read_unaligned(bytes.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70)
                };
                let path =
                    Self::read_c_string_lossy(&bytes[size_of::<IMAGE_DEBUG_CV_INFO_PDB70>()..]);
                let summary = format!("CodeView RSDS age={} path={}", image.Age, path);
                let job = Self::build_download_job(&path, image.Signature, image.Age)?;
                Ok((summary, Some(job)))
            }
            b"NB10" => {
                if bytes.len() < 16 {
                    return Err(Error::DebugInfo("NB10 entry truncated".to_string()));
                }
                let age = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                let path = Self::read_c_string_lossy(&bytes[16..]);
                Ok((format!("CodeView NB10 age={} path={}", age, path), None))
            }
            _ => Err(Error::DebugInfo("unknown magic number".to_string())),
        }
    }

    fn read_c_string_lossy(bytes: &[u8]) -> String {
        let nul = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..nul]).into_owned()
    }

    fn build_download_job(
        pdb_file_name: &str,
        guid: GUID,
        age: u32,
    ) -> Result<(DownloadJob, u128)> {
        let server_name = Self::symbol_server_file_name(pdb_file_name);
        let guid_str = format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            guid.Data1,
            guid.Data2,
            guid.Data3,
            guid.Data4[0],
            guid.Data4[1],
            guid.Data4[2],
            guid.Data4[3],
            guid.Data4[4],
            guid.Data4[5],
            guid.Data4[6],
            guid.Data4[7],
        );

        let index_path = format!("{}/{}{:X}/{}", server_name, guid_str, age, server_name);
        let urls: Vec<String> = pdb_servers()
            .iter()
            .map(|base| format!("{}/{}", base.trim_end_matches('/'), index_path))
            .collect();

        let stem = server_name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(server_name);

        let filename = format!("{}.{}{:X}.pdb", stem, guid_str, age);
        let storage_dir = symbols_directory().ok_or(Error::StorageNotFound)?;
        let path = storage_dir.join(&filename);

        let guid = guid_to_u128(guid);
        let job = DownloadJob {
            urls,
            path,
            filename: format!("{}.pdb", stem),
        };

        Ok((job, guid))
    }

    /// Ensure the module's on-disk PE image (matched by TimeDateStamp +
    /// SizeOfImage, the symbol-server image key) is in the image cache,
    /// downloading it if absent, and return its path. Lets the unwinder recover
    /// read-only data (unwind tables) when the in-memory `.pdata` is paged out.
    pub fn ensure_module_image_on_disk(
        &self,
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<PathBuf> {
        let job = Self::build_image_download_job(image_file_name, time_date_stamp, size_of_image)?;
        download_job(&job, ProgressBar::new(0))?;
        Ok(job.path)
    }

    pub fn build_image_download_job(
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<DownloadJob> {
        let server_name = Self::symbol_server_file_name(image_file_name);
        let image_id = format!("{time_date_stamp:08X}{size_of_image:X}");
        let index_path = format!("{}/{}/{}", server_name, image_id, server_name);
        let urls: Vec<String> = pdb_servers()
            .iter()
            .map(|base| format!("{}/{}", base.trim_end_matches('/'), index_path))
            .collect();
        let storage_dir = images_directory().ok_or(Error::StorageNotFound)?;
        let path = storage_dir.join(format!("{}.{}", image_id, server_name));

        Ok(DownloadJob {
            urls,
            path,
            filename: server_name.to_string(),
        })
    }

    fn symbol_server_file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    // TODO (everywhere) use MemoryOps, not KvmHandle...
    // TODO (everywhere) propagate errors with format!
    // NOTE dont check for more than 1 CV entry, there shouldn't be more than 1
    pub fn load_from_binary(&self, object: &mut WinObject, name: &str) -> Result<Option<u128>> {
        let view = object.view().ok_or(Error::ViewFailed)?;
        let debug = view.debug()?;

        if let Some((job, guid)) = Self::download_job_from_debug(&debug)? {
            download_job(&job, ProgressBar::new(0))?;
            self.ensure_pdb_loaded(guid, &job.path)?;

            let module_key = Self::module_key(object.dtb(), object.base_address);
            if !self.modules.contains_key(&module_key) {
                self.modules.insert(
                    module_key,
                    LoadedModule {
                        name: name.to_string(),
                        guid,
                        base_address: object.base_address,
                        size: object.binary_size().try_into().unwrap_or(u32::MAX),
                        dtb: object.dtb(),
                    },
                );
            }

            return Ok(Some(guid));
        }

        Ok(None)
    }

    /// Load symbols for a module using its image metadata (TimeDateStamp +
    /// SizeOfImage) when the PE header can't be read from memory — the common
    /// case for ntoskrnl in triage dumps.  Downloads the PE from Microsoft's
    /// symbol server, extracts the PDB GUID, downloads the PDB, and registers
    /// the module.
    pub fn load_from_module_info(
        &self,
        name: &str,
        base_address: VirtAddr,
        dtb: Dtb,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<Option<u128>> {
        let image_job = Self::build_image_download_job(name, time_date_stamp, size_of_image)?;
        download_job(&image_job, ProgressBar::new(0))?;

        let Some((pdb_job, guid)) = Self::extract_download_job_from_image_file(&image_job.path)?
        else {
            return Ok(None);
        };

        download_job(&pdb_job, ProgressBar::new(0))?;
        self.ensure_pdb_loaded(guid, &pdb_job.path)?;

        let module_key = Self::module_key(dtb, base_address);
        if !self.modules.contains_key(&module_key) {
            self.modules.insert(
                module_key,
                LoadedModule {
                    name: name.to_string(),
                    guid,
                    base_address,
                    size: size_of_image,
                    dtb,
                },
            );
        }

        Ok(Some(guid))
    }

    pub fn has_guid(&self, guid: u128) -> bool {
        self.pdbs.contains_key(&guid)
    }

    pub fn extract_download_job<B: MemoryOps<PhysAddr>>(
        backend: &B,
        dtb: Dtb,
        module_name: &str,
        base_address: VirtAddr,
    ) -> Result<ModuleSymbolDiscovery> {
        let addr_space = memory::AddressSpace::new(backend, dtb);
        match Self::extract_download_job_from_memory(&addr_space, base_address) {
            Ok(Some((job, guid))) => Ok(ModuleSymbolDiscovery::Ready {
                job,
                guid,
                source: ModuleSymbolSource::Memory,
            }),
            Ok(None) => Self::plan_image_fallback(&addr_space, module_name, base_address),
            Err(Error::BadVirtualAddress(_))
            | Err(Error::AddressNotInDump(_))
            | Err(Error::PartialRead(_))
            | Err(Error::DebugInfo(_)) => {
                Self::plan_image_fallback(&addr_space, module_name, base_address)
            }
            Err(err) => Err(err),
        }
    }

    pub fn load_downloaded_pdb(&self, load: &ModuleSymbolLoad) -> Result<()> {
        let module_key = Self::module_key(load.dtb, load.module.base_address);
        if let Some(existing) = self.modules.get(&module_key) {
            debug_assert_eq!(existing.guid, load.guid);
            self.set_module_symbol_status(
                load.dtb,
                load.module.base_address,
                ModuleSymbolStatus::Loaded,
            );
            self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());
            return Ok(());
        }

        self.ensure_pdb_loaded(load.guid, &load.job.path)?;
        self.modules.insert(module_key, load.loaded_module());
        self.set_module_symbol_status(
            load.dtb,
            load.module.base_address,
            ModuleSymbolStatus::Loaded,
        );
        self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());

        Ok(())
    }

    fn download_job_from_debug<'a, P>(
        debug: &pelite::pe64::debug::Debug<'a, P>,
    ) -> Result<Option<(DownloadJob, u128)>>
    where
        P: Pe<'a>,
    {
        let mut first_error = None;

        for dir in debug.iter() {
            match dir.entry() {
                Ok(entry) => {
                    if let Some(CodeView::Cv70 {
                        image,
                        pdb_file_name,
                    }) = entry.as_code_view()
                    {
                        let pdb_path = pdb_file_name.to_string();
                        let (job, guid) =
                            Self::build_download_job(&pdb_path, image.Signature, image.Age)?;
                        return Ok(Some((job, guid)));
                    }
                }
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err.into());
        }

        Ok(None)
    }

    fn extract_download_job_from_memory<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let Some((debug_rva, debug_size)) =
            Self::read_debug_directory_location(memory, base_address)?
        else {
            return Ok(None);
        };

        for entry in
            Self::read_debug_directory_entries(memory, base_address, debug_rva, debug_size)?
        {
            if entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
                continue;
            }

            let (_, job) = Self::read_codeview_from_memory(memory, base_address, &entry)?;
            if let Some(job) = job {
                return Ok(Some(job));
            }
        }

        Ok(None)
    }

    fn plan_image_fallback<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        module_name: &str,
        base_address: VirtAddr,
    ) -> Result<ModuleSymbolDiscovery> {
        let (time_date_stamp, size_of_image) = Self::read_image_lookup_info(memory, base_address)?;
        let image_job =
            Self::build_image_download_job(module_name, time_date_stamp, size_of_image)?;
        Ok(ModuleSymbolDiscovery::NeedsImage { image_job })
    }

    pub fn extract_download_job_from_image_file(
        image_path: &Path,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let file = File::open(image_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let pe = PeFile::from_bytes(&mmap[..])?;
        let debug = pe.debug()?;
        Self::download_job_from_debug(&debug)
    }

    fn read_image_lookup_info<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<(u32, u32)> {
        let mut header_buf = [0u8; 0x1000];
        memory.read_bytes(base_address, &mut header_buf)?;
        let view = PeView::from_bytes(&header_buf)?;
        Ok((
            view.file_header().TimeDateStamp,
            view.optional_header().SizeOfImage,
        ))
    }

    fn ensure_pdb_loaded(&self, guid: u128, path: &Path) -> Result<()> {
        if self.pdbs.contains_key(&guid) {
            return Ok(());
        }

        if !path.exists() {
            return Err(Error::PdbNotFound(path.to_path_buf()));
        }

        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let mmap = Arc::new(mmap);
        let mmap_slice: &[u8] = &mmap;

        let static_slice: &'static [u8] = unsafe { std::mem::transmute(mmap_slice) };
        let cursor = Cursor::new(static_slice);
        let pdb = pdb2::PDB::open(cursor)?;

        // Exactly one loader may win per guid: parallel loads of two modules
        // sharing a PDB both get past the contains_key fast path, and a plain
        // insert would replace the winner's Arc<Mmap>, unmapping pages the
        // stored PDB's 'static cursor still points into (a cold-cache SIGSEGV).
        // The loser drops its own pdb+mmap pair instead. `build_index` takes
        // the pdbs shard again, so it must run after the entry guard drops.
        match self.pdbs.entry(guid) {
            Entry::Occupied(_) => return Ok(()),
            Entry::Vacant(entry) => {
                self.mmaps.insert(guid, mmap);
                entry.insert(pdb.into());
            }
        }
        self.build_index(guid);

        Ok(())
    }

    pub fn merged_symbol_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let total_modules = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| module.dtb == filter_dtb))
            .count();
        let progress = ProgressBar::new((total_modules + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message("Building symbol completions");

        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index.get(&module.guid) {
                all_strings.extend(index.names.iter().cloned());
            }

            progress.inc(1);
        }

        all_strings.sort();
        all_strings.dedup();

        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex { names: all_strings }
    }

    pub fn merged_types_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let total_modules = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| module.dtb == filter_dtb))
            .count();
        let progress = ProgressBar::new((total_modules + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message("Building type completions");

        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index_types.get(&module.guid) {
                all_strings.extend(index.names.iter().cloned());
            }

            progress.inc(1);
        }

        all_strings.sort();
        all_strings.dedup();

        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex { names: all_strings }
    }

    pub fn merged_enum_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let total_modules = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| module.dtb == filter_dtb))
            .count();
        let progress = ProgressBar::new((total_modules + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message("Building enum completions");

        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index_enums.get(&module.guid) {
                all_strings.extend(index.names.iter().cloned());
            }

            progress.inc(1);
        }

        all_strings.sort();
        all_strings.dedup();

        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex { names: all_strings }
    }

    pub fn find_type_across_modules(&self, dtb: Dtb, type_name: &str) -> Option<TypeInfo> {
        // Type layouts are address-space independent, so a kernel type must
        // resolve to the kernel's definition even while attached to a user
        // process whose modules (e.g. ntdll) define same-named-but-different
        // types or omit kernel-only ones. Consult the kernel module first, then
        // fall back to the current address space's modules for user-mode types.
        //
        // NOTE this hands a WOW64 (32-bit) process the kernel's 64-bit layout
        // for a shared type name instead of its own 32-bit one; revisit with
        // `module!type` qualification if that ever matters
        let kernel_guid = self.kernel_guid();
        if let Some(guid) = kernel_guid
            && let Some(type_info) = self.dump_struct_with_types(guid, type_name)
        {
            return Some(type_info);
        }
        for module in self.modules.iter() {
            if module.dtb != dtb || Some(module.guid) == kernel_guid {
                continue;
            }
            if let Some(type_info) = self.dump_struct_with_types(module.guid, type_name) {
                return Some(type_info);
            }
        }
        None
    }

    /// Variants `(name, value)` of an enum, searched across the modules in the
    /// current address space (mirrors [`Self::find_type_across_modules`]).
    pub fn find_enum_across_modules(
        &self,
        dtb: Dtb,
        enum_name: &str,
    ) -> Option<Vec<(String, i64)>> {
        // Kernel-first for the same reason as `find_type_across_modules`: enum
        // definitions don't depend on the attached address space.
        let kernel_guid = self.kernel_guid();
        if let Some(guid) = kernel_guid
            && let Some(variants) = self.enum_variants(guid, enum_name)
        {
            return Some(variants);
        }
        for module in self.modules.iter() {
            if module.dtb != dtb || Some(module.guid) == kernel_guid {
                continue;
            }
            if let Some(variants) = self.enum_variants(module.guid, enum_name) {
                return Some(variants);
            }
        }
        None
    }

    /// Error text for a name that didn't resolve as a struct/union: point at the
    /// enum tooling when it's actually an enum, else "unknown type". Keeps the
    /// hint identical across the REPL, SDK, and MCP.
    pub fn unresolved_type_message(&self, dtb: Dtb, name: &str) -> String {
        if self.find_enum_across_modules(dtb, name).is_some() {
            format!("{name} is an enum; use enum_values")
        } else {
            format!("unknown type: {name}")
        }
    }

    pub fn find_symbol_across_modules(&self, dtb: Dtb, symbol_name: &str) -> Option<VirtAddr> {
        self.find_symbol_with_module(dtb, symbol_name)
            .map(|(addr, _)| addr)
    }

    /// Like `find_symbol_across_modules`, but also returns the resolving
    /// module's short name (for namespaced display, e.g. `nt!KiSwapThread`).
    pub fn find_symbol_with_module(
        &self,
        dtb: Dtb,
        symbol_name: &str,
    ) -> Option<(VirtAddr, String)> {
        // `module!symbol` restricts the lookup to the named module (by short
        // name, e.g. `nt!KiSwapThread`); a bare name matches in any module
        let (module_filter, name) = match symbol_name.split_once('!') {
            Some((module, name)) => (Some(module), name),
            None => (None, symbol_name),
        };
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            let short = ModuleInfo::derive_short_name(&module.name);
            if let Some(filter) = module_filter
                && !short.eq_ignore_ascii_case(filter)
            {
                continue;
            }
            if let Some(rva) = self.symbol_rva(module.guid, name) {
                return Some((module.base_address + rva as u64, short));
            }
        }
        None
    }

    /// Fuzzy-search symbol names within a single module (by short name, e.g.
    /// `nt`). Backs `module!<prefix>` completion.
    pub fn search_symbols_in_module(
        &self,
        dtb: Dtb,
        module_short: &str,
        query: &str,
        limit: usize,
    ) -> Vec<String> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            if !ModuleInfo::derive_short_name(&module.name).eq_ignore_ascii_case(module_short) {
                continue;
            }
            if let Some(index) = self.index.get(&module.guid) {
                return index.search(query, limit);
            }
        }
        Vec::new()
    }

    pub fn find_closest_symbol_for_address(
        &self,
        dtb: Dtb,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }

            if module.contains_address(address)
                && let Some((sym_name, offset)) =
                    self.closest_symbol(module.guid, module.base_address, address)
            {
                let short_name = ModuleInfo::derive_short_name(&module.name);
                return Some((short_name, sym_name, offset));
            }
        }
        None
    }

    pub fn format_closest_symbol_for_address(&self, dtb: Dtb, address: VirtAddr) -> Option<String> {
        self.find_closest_symbol_for_address(dtb, address)
            .map(|(module, name, offset)| format_symbol_with_offset(&module, &name, offset))
    }

    pub fn find_module_for_address(&self, dtb: Dtb, address: VirtAddr) -> Option<LoadedModule> {
        self.modules
            .iter()
            .find(|module| module.dtb == dtb && module.contains_address(address))
            .map(|module| module.clone())
    }

    fn build_index(&self, guid: u128) -> Option<()> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        let mut strings: Vec<String> = Vec::new();
        let mut rvas: HashMap<String, u32> = HashMap::new();

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse() {
                let name: String = data.name.to_string().into();
                if let Some(rva) = data.offset.to_rva(&address_map) {
                    rvas.insert(name.clone(), rva.0);
                }
                strings.push(name);
            }
        }

        strings.sort();
        strings.dedup();

        self.index.insert(guid, SymbolIndex { names: strings });
        self.symbol_rvas.insert(guid, rvas);

        // NOW FOR TYPES!
        let mut type_strings: Vec<String> = Vec::new();
        let mut enum_strings: Vec<String> = Vec::new();

        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(type_data) = typ.parse() {
                match type_data {
                    TypeData::Class(class)
                        if !class.properties.forward_reference()
                            && class.name.to_string() != "<anonymous-tag>" =>
                    {
                        type_strings.push(class.name.to_string().into());
                    }
                    TypeData::Enumeration(en)
                        if !en.properties.forward_reference()
                            && en.name.to_string() != "<anonymous-tag>" =>
                    {
                        enum_strings.push(en.name.to_string().into());
                    }
                    _ => {}
                }
            }
        }

        type_strings.sort();
        type_strings.dedup();
        enum_strings.sort();
        enum_strings.dedup();

        self.index_types.insert(
            guid,
            SymbolIndex {
                names: type_strings,
            },
        );
        self.index_enums.insert(
            guid,
            SymbolIndex {
                names: enum_strings,
            },
        );

        Some(())
    }

    // pub fn symbol_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    // pub fn types_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index_types.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    pub fn symbol_rva<S>(&self, guid: u128, symbol_name: S) -> Option<u32>
    where
        S: AsRef<str>,
    {
        let symbol_name = symbol_name.as_ref();

        // fast path: the prebuilt name->rva map (built by build_index). It covers
        // every public the scan below would find, minus those whose offset has no
        // RVA (the scan returns 0 for those; here they're simply absent -> None)
        if let Some(map) = self.symbol_rvas.get(&guid) {
            return map.get(symbol_name).copied();
        }

        // fallback: scan the PDB when the index hasn't been built for this module
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse()
                && data.name.to_string() == symbol_name
            {
                return Some(data.offset.to_rva(&address_map).unwrap_or_default().0);
            }
        }

        None
    }

    pub fn closest_symbol(
        &self,
        guid: u128,
        base_address: VirtAddr,
        address: VirtAddr,
    ) -> Option<(String, u32)> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        let mut closest: Option<(String, u32)> = None;
        let max_offset = 8192u32;

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse()
                && let Some(rva) = data.offset.to_rva(&address_map)
            {
                let symbol_address = base_address + rva.0 as u64;
                if address.0 >= symbol_address.0 {
                    let offset = (address.0 - symbol_address.0) as u32;
                    if offset <= max_offset {
                        if let Some((_, best_offset)) = closest {
                            if offset < best_offset {
                                closest = Some((data.name.to_string().into(), offset));
                            }
                        } else {
                            closest = Some((data.name.to_string().into(), offset));
                        }
                    }
                }
            }
        }

        closest
    }

    fn type_size<'p>(
        &self,
        finder: &pdb2::TypeFinder<'p>,
        index: pdb2::TypeIndex,
        ptr_size: u64,
    ) -> pdb2::Result<u64> {
        let item = finder.find(index)?;
        match item.parse()? {
            pdb2::TypeData::Primitive(data) => {
                if data.indirection.is_some() {
                    return Ok(ptr_size);
                }

                match data.kind {
                    pdb2::PrimitiveKind::Void => Ok(0),

                    pdb2::PrimitiveKind::Char
                    | pdb2::PrimitiveKind::RChar
                    | pdb2::PrimitiveKind::UChar
                    | pdb2::PrimitiveKind::I8
                    | pdb2::PrimitiveKind::U8
                    | pdb2::PrimitiveKind::Bool8 => Ok(1),

                    pdb2::PrimitiveKind::WChar
                    | pdb2::PrimitiveKind::RChar16
                    | pdb2::PrimitiveKind::Short
                    | pdb2::PrimitiveKind::UShort
                    | pdb2::PrimitiveKind::I16
                    | pdb2::PrimitiveKind::U16 => Ok(2),

                    pdb2::PrimitiveKind::Long
                    | pdb2::PrimitiveKind::ULong
                    | pdb2::PrimitiveKind::I32
                    | pdb2::PrimitiveKind::U32
                    | pdb2::PrimitiveKind::Bool32
                    | pdb2::PrimitiveKind::F32
                    | pdb2::PrimitiveKind::RChar32 => Ok(4),

                    pdb2::PrimitiveKind::Quad
                    | pdb2::PrimitiveKind::UQuad
                    | pdb2::PrimitiveKind::I64
                    | pdb2::PrimitiveKind::U64
                    | pdb2::PrimitiveKind::F64 => Ok(8),

                    pdb2::PrimitiveKind::Octa | pdb2::PrimitiveKind::UOcta => Ok(16),

                    _ => Ok(0),
                }
            }
            pdb2::TypeData::Class(data) => Ok(data.size), // NOTE this might (probably will) return 0
            pdb2::TypeData::Union(data) => Ok(data.size), // FIXME possibly? ^^
            pdb2::TypeData::Pointer(_) => Ok(ptr_size),
            pdb2::TypeData::Modifier(data) => {
                self.type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Enumeration(data) => {
                self.type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Array(data) => {
                Ok(data.dimensions.iter().fold(0, |acc, &x| acc + x as u64))
            }
            pdb2::TypeData::Bitfield(data) => {
                self.type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Procedure(_) => Ok(ptr_size),
            _ => Ok(0),
        }
    }

    fn resolve_type<'p>(
        &self,
        finder: &TypeFinder<'p>,
        index: TypeIndex,
    ) -> pdb2::Result<ParsedType> {
        let item = finder.find(index)?;
        let parsed = item.parse()?;

        match parsed {
            pdb2::TypeData::Primitive(data) => {
                let name = match data.kind {
                    PrimitiveKind::Void => "void",
                    PrimitiveKind::Char | PrimitiveKind::I8 => "CHAR",
                    PrimitiveKind::UChar | PrimitiveKind::U8 => "UCHAR",
                    PrimitiveKind::RChar => "CHAR",
                    PrimitiveKind::WChar => "WCHAR",
                    PrimitiveKind::RChar16 => "char16_t",
                    PrimitiveKind::RChar32 => "char32_t",
                    PrimitiveKind::Short | PrimitiveKind::I16 => "SHORT",
                    PrimitiveKind::UShort | PrimitiveKind::U16 => "USHORT",
                    PrimitiveKind::Long | PrimitiveKind::I32 => "LONG",
                    PrimitiveKind::ULong | PrimitiveKind::U32 => "ULONG",
                    PrimitiveKind::Quad | PrimitiveKind::I64 => "LONGLONG",
                    PrimitiveKind::UQuad | PrimitiveKind::U64 => "ULONGLONG",
                    PrimitiveKind::Octa => "INT128",
                    PrimitiveKind::UOcta => "UINT128",
                    PrimitiveKind::F32 => "float",
                    PrimitiveKind::F64 => "double",
                    PrimitiveKind::Bool8 | PrimitiveKind::Bool32 => "bool",
                    _ => "__unknown_t",
                };
                let primitive = ParsedType::Primitive(name.to_string());
                if data.indirection.is_some() {
                    Ok(ParsedType::Pointer(Box::new(primitive)))
                } else {
                    Ok(primitive)
                }
            }

            TypeData::Class(data) => Ok(ParsedType::Struct(data.name.to_string().into_owned())),
            TypeData::Union(data) => Ok(ParsedType::Union(data.name.to_string().into_owned())),
            TypeData::Enumeration(data) => Ok(ParsedType::Enum(data.name.to_string().into_owned())),

            TypeData::Pointer(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;
                Ok(ParsedType::Pointer(Box::new(inner)))
            }

            TypeData::Array(data) => {
                let inner = self.resolve_type(finder, data.element_type)?;
                let count = data.dimensions.first().unwrap_or(&0);
                let mut sizeof_type = self.type_size(finder, data.element_type, 8)? as u32;
                if sizeof_type == 0 {
                    sizeof_type = 1;
                }

                Ok(ParsedType::Array(Box::new(inner), count / sizeof_type))
            }

            TypeData::Modifier(data) => self.resolve_type(finder, data.underlying_type),
            TypeData::Bitfield(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;

                Ok(ParsedType::Bitfield {
                    underlying: Box::new(inner),
                    pos: data.position,
                    len: data.length,
                })
            }

            pdb2::TypeData::Procedure(data) => {
                let return_type = if let Some(idx) = data.return_type {
                    self.resolve_type(finder, idx)?
                } else {
                    ParsedType::Primitive("void".to_string())
                };

                let mut args = Vec::new();
                if let Ok(arg_item) = finder.find(data.argument_list)
                    && let Ok(pdb2::TypeData::ArgumentList(list)) = arg_item.parse()
                {
                    for arg_idx in list.arguments {
                        let arg_type = self.resolve_type(finder, arg_idx)?;
                        args.push(arg_type);
                    }
                }

                Ok(ParsedType::Function(Box::new(return_type), args))
            }

            _ => Ok(ParsedType::Unknown),
        }
    }

    fn process_field_list<'p>(
        &self,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        fields_map: &mut HashMap<String, FieldInfo>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;

        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Member(member) = field {
                    let name = member.name.to_string().into_owned();
                    let offset = member.offset;

                    let type_info = self.resolve_type(type_finder, member.field_type)?;

                    fields_map.insert(
                        name,
                        FieldInfo {
                            offset: offset as u32,
                            size: self.type_size(type_finder, member.field_type, 8)?,
                            type_data: type_info,
                        },
                    );
                }
            }

            if let Some(more_fields) = list.continuation {
                self.process_field_list(type_finder, more_fields, fields_map)?;
            }
        }
        Ok(())
    }

    pub fn dump_struct_with_types<S>(&self, guid: u128, struct_name: S) -> Option<TypeInfo>
    where
        S: Into<String> + AsRef<str>,
    {
        // A hit skips the full PDB type-stream scan below. Cloning the cached
        // layout is cheap next to that scan, so callers keep their owned return
        let cache_key = (guid, struct_name.as_ref().to_string());
        if let Some(cached) = self.type_cache.get(&cache_key) {
            return Some((**cached).clone());
        }

        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse()
                && class.name.to_string() == struct_name.as_ref()
                && !class.properties.forward_reference()
            {
                let mut fields_map: HashMap<String, FieldInfo> = HashMap::new();
                if let Some(field_index) = class.fields {
                    self.process_field_list(&type_finder, field_index, &mut fields_map)
                        .ok()?;
                }

                let type_info = TypeInfo {
                    name: struct_name.into(),
                    size: class.size as usize,
                    fields: fields_map,
                };
                self.type_cache
                    .insert(cache_key, Arc::new(type_info.clone()));
                return Some(type_info);
            }
        }

        None
    }

    /// Variants `(name, value)` of a PDB enum, in declaration order. Enums live
    /// in the type stream but aren't in the (class-only) type index, so this
    /// scans like `dump_struct_with_types`. Lets callers map a raw enum value
    /// (e.g. an `_MI_SYSTEM_VA_TYPE` region tag) back to its name.
    pub fn enum_variants<S>(&self, guid: u128, enum_name: S) -> Option<Vec<(String, i64)>>
    where
        S: AsRef<str>,
    {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Enumeration(en)) = typ.parse()
                && en.name.to_string() == enum_name.as_ref()
                && !en.properties.forward_reference()
            {
                let mut out = Vec::new();
                self.collect_enum_variants(&type_finder, en.fields, &mut out)
                    .ok()?;
                return Some(out);
            }
        }
        None
    }

    fn collect_enum_variants<'p>(
        &self,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        out: &mut Vec<(String, i64)>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;
        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Enumerate(e) = field {
                    out.push((e.name.to_string().into_owned(), variant_to_i64(&e.value)));
                }
            }
            if let Some(more) = list.continuation {
                self.collect_enum_variants(type_finder, more, out)?;
            }
        }
        Ok(())
    }
}

/// A pdb2 enum-constant value, widened to `i64` (enum tags are small).
fn variant_to_i64(v: &pdb2::Variant) -> i64 {
    match *v {
        pdb2::Variant::U8(x) => x as i64,
        pdb2::Variant::U16(x) => x as i64,
        pdb2::Variant::U32(x) => x as i64,
        pdb2::Variant::U64(x) => x as i64,
        pdb2::Variant::I8(x) => x as i64,
        pdb2::Variant::I16(x) => x as i64,
        pdb2::Variant::I32(x) => x as i64,
        pdb2::Variant::I64(x) => x,
    }
}

impl SymbolIndex {
    /// Fuzzy substring search over the names, ranked best-first. Smart-case
    /// (case-insensitive unless the query has uppercase), so `process` matches
    /// `PsGetProcessId`. Empty query returns the first `limit` names.
    pub fn search(&self, query: &str, limit: usize) -> Vec<String> {
        if query.is_empty() || limit == 0 {
            return self.names.iter().take(limit).cloned().collect();
        }

        let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);

        // Fuzzy-scoring every name is the per-keystroke hot path: an attached
        // GUI process can pull in hundreds of thousands of publics across its
        // loaded modules, and `Pattern::match_list` scores them on a single
        // thread. Spread the scan across cores instead; each rayon job keeps
        // its own matcher and utf32 scratch buffer (both reused across the items
        // that job sees, like the original thread-local matcher did).
        let mut scored: Vec<(u32, &String)> = self
            .names
            .par_iter()
            .map_init(
                || (Matcher::new(Config::DEFAULT), Vec::new()),
                |(matcher, buf), name| {
                    pattern
                        .score(Utf32Str::new(name, buf), matcher)
                        .map(|score| (score, name))
                },
            )
            .filter_map(|scored| scored)
            .collect();

        // Only the top `limit` matches are shown, so partial-select them instead
        // of fully sorting every match; a short, broad query can match most of
        // the list, and the full O(n log n) sort there is what stings. Ties break
        // alphabetically (names are unique) for a stable, predictable ordering.
        let by_rank =
            |a: &(u32, &String), b: &(u32, &String)| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1));
        if scored.len() > limit {
            scored.select_nth_unstable_by(limit - 1, by_rank);
            scored.truncate(limit);
        }
        scored.sort_unstable_by(by_rank);
        scored.into_iter().map(|(_, name)| name.clone()).collect()
    }
}
