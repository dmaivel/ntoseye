use crate::{
    guest::ModuleInfo,
    layout::{EnumDef, ParsedType, TypeInfo},
    pe::PeImage,
    types::{Dtb, VirtAddr},
};
use dashmap::DashMap;
use memmap2::Mmap;
use pdb2::TypeIndex;
use spin::{Mutex, RwLock};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Cursor,
    path::PathBuf,
    sync::{
        Arc, LazyLock, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
};

pub static FORCE_DOWNLOADS: OnceLock<bool> = OnceLock::new();

pub static PDB_SERVERS: OnceLock<Vec<String>> = OnceLock::new();

const DEFAULT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// The symbol path a store starts with: the cache, then `--pdb-server` and
/// `NTOSEYE_PDB_SERVERS` entries ahead of Microsoft's server.
static DEFAULT_SYMBOL_SOURCES: LazyLock<Vec<SymbolSource>> = LazyLock::new(|| {
    let mut sources = vec![SymbolSource::Cache];
    let servers = PDB_SERVERS.get().cloned().unwrap_or_default();
    sources.extend(servers.into_iter().map(SymbolSource::Http));
    sources.extend(
        std::env::var("NTOSEYE_PDB_SERVERS")
            .ok()
            .iter()
            .flat_map(|env| env.split(';'))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| SymbolSource::Http(s.to_string())),
    );
    sources.push(SymbolSource::Http(DEFAULT_SYMBOL_SERVER.to_string()));
    sources
});

/// `index_path` under every symbol server in the default symbol path.
fn server_urls(index_path: &str) -> Vec<String> {
    DEFAULT_SYMBOL_SOURCES
        .iter()
        .filter_map(|source| match source {
            SymbolSource::Http(base) => {
                Some(format!("{}/{index_path}", base.trim_end_matches('/')))
            }
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolVisibility {
    Public,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedSymbol {
    rva: u32,
    visibility: SymbolVisibility,
    compiland: Option<String>,
}

/// One address-bearing record of the RVA-sorted index behind
/// [`SymbolStore::closest_symbol`]. Records sharing an RVA are ordered by
/// the resolution preference (public first, then name, then compiland), so
/// the first record of an equal-RVA run is the one to report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AddressEntry {
    rva: u32,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolCandidate {
    pub module: String,
    pub address: VirtAddr,
    pub visibility: SymbolVisibility,
    pub compiland: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolIndexDiagnostic {
    pub phase: &'static str,
    pub compiland: Option<String>,
    pub message: String,
}

pub struct SymbolStore {
    pdbs: DashMap<u128, Mutex<pdb2::PDB<'static, Cursor<&'static [u8]>>>>,

    mmaps: DashMap<u128, Arc<Mmap>>,
    pdb_ages: DashMap<u128, u32>,
    /// GUID -> pointer width of the PDB's target machine (see
    /// [`TypeInfo::pointer_size`]).
    pdb_pointer_sizes: DashMap<u128, u8>,
    index_build_results: DashMap<u128, Arc<OnceLock<std::result::Result<(), String>>>>,
    index: DashMap<u128, SymbolIndex>,
    index_types: DashMap<u128, SymbolIndex>,
    index_enums: DashMap<u128, SymbolIndex>,
    /// GUID -> struct/union name -> (size, field list) of its largest complete
    /// definition (a header-local `_KPCR` stub precedes the real one in
    /// ntoskrnl.pdb). Member types are usually forward references (size 0),
    /// so array element counts and field sizes need the size; layout dumps
    /// need the field list without rescanning the type stream.
    struct_defs: DashMap<u128, HashMap<String, (u64, TypeIndex)>>,
    /// GUID -> symbol name -> every address-bearing PDB record. Private/static
    /// duplicates retain their compiland identity; resolution prefers public
    /// records when present but never collapses distinct candidate addresses.
    symbol_rvas: DashMap<u128, HashMap<String, Vec<IndexedSymbol>>>,
    /// GUID -> the same records sorted by RVA, for address-to-symbol lookups.
    symbol_addresses: DashMap<u128, Vec<AddressEntry>>,
    source_lines: DashMap<u128, Vec<SourceLineEntry>>,
    index_diagnostics: DashMap<u128, Vec<SymbolIndexDiagnostic>>,

    /// (guid, struct name) -> parsed layout. `dump_struct_with_types`
    /// otherwise rescans the entire PDB type stream on every call; keying on
    /// guid makes this self-coherent (a reloaded module gets a new guid, so a
    /// stale entry can never be returned).
    /// `None` remembers a type the PDB does not define, so repeated misses
    /// (`_MM_SESSION_SPACE` per process) cost a map probe, not a stream scan.
    type_cache: DashMap<(u128, String), Option<Arc<TypeInfo>>>,
    /// (guid, enum name) -> definition, `None` for a miss; see
    /// [`Self::enum_def`].
    enum_cache: DashMap<(u128, String), Option<Arc<EnumDef>>>,

    /// (guid, procedure-relative RVA) -> locals in scope there. A single
    /// lookup walks the whole type stream and every compiland's symbols, and
    /// expression evaluation now consults locals for every bare identifier,
    /// so a conditional breakpoint would otherwise rescan the PDB on each hit.
    /// Locations are static PDB recipes (registers are applied at use time),
    /// so an entry stays valid for the lifetime of the guid.
    locals_cache: DashMap<(u128, u32), Option<Arc<Vec<ProcedureLocal>>>>,
    /// Complete on-disk images by cache path. A stack walk builds its module
    /// cache anew, and expanding a kernel image is 13 MiB of copying it
    /// should not repeat per thread.
    on_disk_images: DashMap<PathBuf, Arc<PeImage>>,

    modules: DashMap<(Dtb, u64), LoadedModule>,
    module_status: DashMap<(Dtb, u64), ModuleSymbolStatus>,
    module_source: DashMap<(Dtb, u64), ModuleSymbolSource>,
    sources: RwLock<Vec<SymbolSource>>,
    source_paths: RwLock<Vec<SourcePathMapping>>,

    /// GUID of the kernel (`ntoskrnl`) module. Type/enum *layout* lookups are
    /// address-space independent, so they must always prefer the kernel's
    /// definitions over same-named user-mode types (e.g. ntdll's `_KPRCB`) and
    /// over kernel-only types the attached process simply omits. Resolution
    /// consults this guid first regardless of the attached DTB; updated whenever
    /// the kernel module (re)loads.
    kernel_guid: Mutex<Option<u128>>,
    /// Address space kernel modules are registered under. Kernel space is
    /// mapped into every process, so lookups scoped to a user DTB also see
    /// these modules (`bp nt!NtClose` from a process context).
    kernel_dtb: Mutex<Option<Dtb>>,

    /// PDBs of modules identified in earlier sessions; opened on first use so
    /// building a store touches no files.
    identities: OnceLock<ModuleIdentities>,

    /// Bumped whenever a module's symbols become available, so a session can
    /// notice a load it did not perform itself (a background fetch, a lazy
    /// frame load) and re-resolve deferred breakpoints.
    load_generation: AtomicU64,
    /// Lines the store wants the host to see at its next output boundary:
    /// background fetch start/finish. Drained by
    /// [`crate::session::Session::take_notices`].
    notices: Mutex<Vec<String>>,
    /// Module images being downloaded by [`SymbolStore::image_or_fetch_later`],
    /// so a repeated request does not start a second download.
    image_fetches: Mutex<HashSet<PathBuf>>,
    /// The background image fetch worker's queue, started with the first
    /// fetch. One download at a time: a gdb connecting asks for every loaded
    /// module's image at once.
    image_queue: Mutex<Option<mpsc::Sender<DownloadJob>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolSource {
    /// ntoseye's managed on-disk symbol cache.
    Cache,
    /// A directory containing either bare PDBs or a conventional symbol store.
    LocalDirectory(PathBuf),
    /// An HTTP(S) symbol server root.
    Http(String),
}

impl fmt::Display for SymbolSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache => match symbols_directory() {
                Some(path) => write!(f, "cache*{}", path.display()),
                None => f.write_str("cache*<unavailable>"),
            },
            Self::LocalDirectory(path) => write!(f, "{}", path.display()),
            Self::Http(url) => f.write_str(url),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePathMapping {
    pub recorded_prefix: Option<String>,
    pub local_root: PathBuf,
}

impl fmt::Display for SourcePathMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.recorded_prefix {
            Some(prefix) => write!(f, "{}={}", prefix, self.local_root.display()),
            None => write!(f, "{}", self.local_root.display()),
        }
    }
}

/// Parse `.sympath` syntax into ordered symbol sources: `;`-separated entries,
/// `cache`/`cache*<dir>` for the managed cache, `srv*<a>*<b>` for a server
/// chain, `http(s)://` for a symbol server, anything else a local directory.
/// Shared by the REPL's `.sympath`/`.sympath+` and the DAP `symbolPath`
/// attach argument.
pub fn parse_symbol_sources<S: AsRef<str>>(args: &[S]) -> Vec<SymbolSource> {
    args.iter()
        .flat_map(|arg| arg.as_ref().split(';'))
        .filter(|entry| !entry.is_empty())
        .flat_map(|entry| {
            if entry.eq_ignore_ascii_case("cache") || entry.starts_with("cache*") {
                vec![SymbolSource::Cache]
            } else if let Some(rest) = entry.strip_prefix("srv*") {
                let parts = rest.split('*').filter(|part| !part.is_empty());
                parts
                    .map(|part| {
                        if part.starts_with("http://") || part.starts_with("https://") {
                            SymbolSource::Http(part.trim_end_matches('/').to_string())
                        } else {
                            SymbolSource::LocalDirectory(part.into())
                        }
                    })
                    .collect()
            } else if entry.starts_with("http://") || entry.starts_with("https://") {
                vec![SymbolSource::Http(entry.trim_end_matches('/').to_string())]
            } else {
                vec![SymbolSource::LocalDirectory(entry.into())]
            }
        })
        .collect()
}

/// Parse `.srcpath` syntax into source-path mappings: `;`-separated entries,
/// each either `<recorded-prefix>=<local-root>` or a bare local root. Shared
/// by the REPL's `.srcpath`/`.srcpath+` and the DAP `sourcePath` attach
/// argument.
pub fn parse_source_paths<S: AsRef<str>>(args: &[S]) -> Vec<SourcePathMapping> {
    args.iter()
        .flat_map(|arg| arg.as_ref().split(';'))
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((recorded, local)) => SourcePathMapping {
                recorded_prefix: Some(recorded.to_string()),
                local_root: local.into(),
            },
            None => SourcePathMapping {
                recorded_prefix: None,
                local_root: entry.into(),
            },
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdbIdentity {
    pub guid: u128,
    pub age: u32,
}

impl PdbIdentity {
    fn matches(self, candidate: Self) -> std::result::Result<(), String> {
        if candidate.guid != self.guid {
            return Err(format!(
                "GUID mismatch (expected {:032X}, found {:032X})",
                self.guid, candidate.guid
            ));
        }
        if candidate.age < self.age {
            return Err(format!(
                "age mismatch (image {}, PDB {}; PDB age must be at least the image age)",
                self.age, candidate.age
            ));
        }
        Ok(())
    }

    fn symbol_store_key(self) -> String {
        // `guid_to_u128` packs the GUID fields big-endian in field order, so
        // the hex of the u128 is the symbol server's GUID spelling.
        format!("{:032X}{:X}", self.guid, self.age)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// Path recorded in the PDB.
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    /// First configured remapping candidate (or first existing candidate).
    pub local_path: Option<PathBuf>,
    pub local_exists: bool,
}

/// The source-line address range containing an instruction. `end` is
/// exclusive; it is `None` when the PDB records neither a length nor a
/// following entry. A debugger uses this extent to step a whole source line
/// at once instead of single-stepping each instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLineExtent {
    /// Source file and line metadata, including any configured path remapping.
    pub location: SourceLocation,
    /// Exclusive line end, when the PDB provides one.
    pub end: Option<VirtAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureLocal {
    pub name: String,
    pub type_name: String,
    /// Structured form of the local's type for hosts that decode it (the DAP
    /// variables tree); `Unknown` means the PDB recipe could not be resolved.
    /// `type_name` remains the display string.
    pub type_data: ParsedType,
    pub byte_size: Option<u64>,
    pub is_parameter: bool,
    pub location: LocalVariableLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalVariableLocation {
    /// The variable's value is held directly in a register.
    Register { register: String },
    /// The variable is stored in memory at register + signed offset.
    RegisterRelative { register: String, offset: i32 },
    /// PDB frame-pointer-relative location without a safely decoded base register.
    FrameRelative { offset: i32 },
    /// The PDB explicitly says the value is absent or uses an unsupported recipe.
    Unavailable { reason: String },
}

impl LocalVariableLocation {
    /// Where the variable lives, in WinDbg's notation (`rcx`, `[rbp-0x18]`,
    /// `[frame+0x10]`). Shared by `dv` and the DAP variables view so the two
    /// describe a location identically.
    pub fn describe(&self) -> String {
        match self {
            Self::Register { register } => register.clone(),
            Self::RegisterRelative { register, offset } => {
                format!("[{register}{}]", signed_hex(*offset))
            }
            Self::FrameRelative { offset } => format!("[frame{}]", signed_hex(*offset)),
            Self::Unavailable { reason } => format!("<{reason}>"),
        }
    }
}

/// Format a signed byte offset as `+0x..`/`-0x..`. Rust's `{:+#x}` renders a
/// negative value as its two's-complement bit pattern, which reads as a huge
/// positive offset.
fn signed_hex(offset: i32) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("+0x{offset:x}")
    }
}

#[derive(Debug, Clone)]
struct SourceLineEntry {
    rva: u32,
    length: Option<u32>,
    location: SourceLocation,
}

pub fn format_symbol_with_offset(module: &str, name: &str, offset: u32) -> String {
    if offset == 0 {
        format!("{module}!{name}")
    } else {
        format!("{module}!{name}+{offset:#x}")
    }
}

static HOME_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

pub fn ntoseye_home() -> Option<PathBuf> {
    HOME_PATH.get_or_init(resolve_ntoseye_home).clone()
}

fn resolve_ntoseye_home() -> Option<PathBuf> {
    let path = user_home_dir()?.join(".ntoseye");
    std::fs::create_dir_all(&path).ok()?;
    Some(path)
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var("SUDO_USER")
        .ok()
        .filter(|user| !user.is_empty())
        .map(|user| {
            if cfg!(target_os = "macos") {
                PathBuf::from(format!("/Users/{user}"))
            } else {
                PathBuf::from(format!("/home/{user}"))
            }
        })
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

/// Whether a lookup in the image cache may download a missing image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFetch {
    CacheOnly,
    Download,
}

/// A file acquisition planned by symbol discovery. PDB jobs carry the RSDS
/// identity and ordered source snapshot needed to validate every candidate.
#[derive(Debug, Clone)]
pub struct DownloadJob {
    pub urls: Vec<String>,
    pub path: PathBuf,
    pub filename: String,
    pdb: Option<PdbRequest>,
}

#[derive(Debug, Clone)]
struct PdbRequest {
    identity: PdbIdentity,
    server_name: String,
    sources: Vec<SymbolSource>,
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolStatus {
    Loaded,
    MissingDebugInfo,
    Skipped,
    Failed(#[allow(dead_code)] String),
    /// Handed to the background fetcher (see
    /// [`crate::guest::Guest::load_module_symbols_or_fetch_later`]); becomes
    /// `Loaded` or `Failed` when it finishes.
    Fetching,
}

impl ModuleSymbolStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::MissingDebugInfo => "no-pdb",
            Self::Skipped => "skipped",
            Self::Failed(_) => "failed",
            Self::Fetching => "fetching",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolSource {
    Memory,
    Image,
    /// Remembered from an earlier session (see [`ModuleIdentities`]).
    Identity,
}

impl ModuleSymbolSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Image => "image",
            Self::Identity => "cached",
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
            short_name: self.module.short_name.clone(),
            guid: self.guid,
            base_address: self.module.base_address,
            size: self.module.size,
            dtb: self.dtb,
        }
    }
}

/// A loaded module with its symbols and address range.
/// Used to track modules across both kernel and user address spaces.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    /// The `module!` qualifier (`nt`, `ntdll`, `ntdll32`); see
    /// [`ModuleInfo::short_name`].
    pub short_name: String,
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
            pdb_ages: DashMap::new(),
            pdb_pointer_sizes: DashMap::new(),
            index_build_results: DashMap::new(),
            index: DashMap::new(),
            index_types: DashMap::new(),
            index_enums: DashMap::new(),
            struct_defs: DashMap::new(),
            symbol_rvas: DashMap::new(),
            symbol_addresses: DashMap::new(),
            source_lines: DashMap::new(),
            index_diagnostics: DashMap::new(),
            type_cache: DashMap::new(),
            enum_cache: DashMap::new(),
            locals_cache: DashMap::new(),
            on_disk_images: DashMap::new(),
            modules: DashMap::new(),
            module_status: DashMap::new(),
            module_source: DashMap::new(),
            sources: RwLock::new(DEFAULT_SYMBOL_SOURCES.clone()),
            source_paths: RwLock::new(Vec::new()),
            kernel_guid: Mutex::new(None),
            kernel_dtb: Mutex::new(None),
            identities: OnceLock::new(),
            load_generation: AtomicU64::new(0),
            notices: Mutex::new(Vec::new()),
            image_fetches: Mutex::new(HashSet::new()),
            image_queue: Mutex::new(None),
        }
    }

    /// See [`SymbolStore::load_generation`] field docs.
    pub fn load_generation(&self) -> u64 {
        self.load_generation.load(Ordering::Acquire)
    }

    pub fn push_notice(&self, notice: String) {
        self.notices.lock().push(notice);
    }

    pub fn take_notices(&self) -> Vec<String> {
        std::mem::take(&mut *self.notices.lock())
    }

    pub fn index_diagnostics(&self, guid: u128) -> Vec<SymbolIndexDiagnostic> {
        self.index_diagnostics
            .get(&guid)
            .map(|diagnostics| diagnostics.clone())
            .unwrap_or_default()
    }

    pub fn symbol_sources(&self) -> Vec<SymbolSource> {
        self.sources.read().clone()
    }

    pub fn set_symbol_sources(&self, sources: Vec<SymbolSource>) {
        *self.sources.write() = sources;
    }

    pub fn append_symbol_source(&self, source: SymbolSource) {
        self.sources.write().push(source);
    }

    pub fn reset_symbol_sources(&self) {
        *self.sources.write() = DEFAULT_SYMBOL_SOURCES.clone();
    }

    pub fn source_paths(&self) -> Vec<SourcePathMapping> {
        self.source_paths.read().clone()
    }

    pub fn set_source_paths(&self, paths: Vec<SourcePathMapping>) {
        *self.source_paths.write() = paths;
    }

    pub fn append_source_path(&self, path: SourcePathMapping) {
        self.source_paths.write().push(path);
    }

    pub fn reset_source_paths(&self) {
        self.source_paths.write().clear();
    }

    /// Record the kernel module's guid so type/enum layout lookups can prefer it
    /// regardless of the attached address space. Called when `ntoskrnl` loads.
    pub fn set_kernel(&self, guid: Option<u128>, dtb: Dtb) {
        *self.kernel_guid.lock() = guid;
        *self.kernel_dtb.lock() = Some(dtb);
    }

    pub fn kernel_guid(&self) -> Option<u128> {
        *self.kernel_guid.lock()
    }

    /// Whether `module` is visible from address space `dtb`: its own space, or
    /// kernel space, which every process maps.
    fn module_in_scope(&self, module: &LoadedModule, dtb: Dtb) -> bool {
        module.dtb == dtb || Some(module.dtb) == *self.kernel_dtb.lock()
    }

    /// Register a module's layouts and public symbol RVAs without a PDB, for
    /// tests that drive guest walks over synthetic memory.
    #[cfg(test)]
    pub fn inject_module_for_test(
        &self,
        guid: u128,
        types: Vec<TypeInfo>,
        symbols: &[(&str, u32)],
    ) {
        for type_info in types {
            self.type_cache
                .insert((guid, type_info.name.clone()), Some(Arc::new(type_info)));
        }
        self.publish_symbol_rvas(
            guid,
            symbols
                .iter()
                .map(|(name, rva)| {
                    (
                        name.to_string(),
                        vec![IndexedSymbol {
                            rva: *rva,
                            visibility: SymbolVisibility::Public,
                            compiland: None,
                        }],
                    )
                })
                .collect(),
        );
        // Symbols became available: what a real load reports through the
        // generation counter.
        self.load_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Register a module with `short_name` in `dtb` so `short_name!` lookups
    /// reach the layouts injected under `guid`.
    #[cfg(test)]
    pub fn register_module_for_test(&self, guid: u128, short_name: &str, dtb: Dtb) {
        let base = VirtAddr(0x1000_0000 * (guid as u64 + 1));
        self.modules.insert(
            Self::module_key(dtb, base),
            LoadedModule {
                name: format!("{short_name}.dll"),
                short_name: short_name.to_string(),
                guid,
                base_address: base,
                size: 0x1000,
                dtb,
            },
        );
    }

    /// Answer `procedure_locals` at `rva` in the module injected under `guid`
    /// with `locals`, for tests that drive locals without a PDB.
    #[cfg(test)]
    pub fn inject_procedure_locals_for_test(
        &self,
        guid: u128,
        rva: u32,
        locals: Vec<ProcedureLocal>,
    ) {
        self.locals_cache
            .insert((guid, rva), Some(Arc::new(locals)));
    }

    /// Register a loaded module and its C13 source-line records without a PDB,
    /// for tests that drive line-granular stepping over synthetic memory. Each
    /// record is `(rva, length, line)`; a `None` length means the next record
    /// bounds it, exactly as a PDB without lengths does.
    #[cfg(test)]
    pub fn inject_source_lines_for_test(
        &self,
        guid: u128,
        dtb: Dtb,
        base: VirtAddr,
        size: u32,
        file: &str,
        records: &[(u32, Option<u32>, u32)],
    ) {
        self.modules.insert(
            Self::module_key(dtb, base),
            LoadedModule {
                name: "driver.sys".to_string(),
                short_name: "driver".to_string(),
                guid,
                base_address: base,
                size,
                dtb,
            },
        );
        self.source_lines.insert(
            guid,
            records
                .iter()
                .map(|(rva, length, line)| SourceLineEntry {
                    rva: *rva,
                    length: *length,
                    location: SourceLocation {
                        file: file.to_string(),
                        line: *line,
                        column: None,
                        local_path: None,
                        local_exists: false,
                    },
                })
                .collect(),
        );
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

    /// Forget selected module registrations and evict PDBs no longer used by
    /// another loaded module, so a subsequent load re-runs source selection and
    /// indexing.
    pub fn invalidate_modules(&self, dtb: Dtb, base_addresses: &[VirtAddr]) {
        let keys = base_addresses
            .iter()
            .map(|base| Self::module_key(dtb, *base))
            .collect::<Vec<_>>();
        let mut candidate_guids = HashSet::new();
        for key in &keys {
            if let Some((_, module)) = self.modules.remove(key) {
                candidate_guids.insert(module.guid);
            }
            self.module_status.remove(key);
            self.module_source.remove(key);
        }

        for guid in candidate_guids {
            if self.modules.iter().any(|module| module.guid == guid) {
                continue;
            }
            if let Some((_, pdb)) = self.pdbs.remove(&guid) {
                drop(pdb);
            }
            self.mmaps.remove(&guid);
            self.pdb_ages.remove(&guid);
            self.index_build_results.remove(&guid);
            self.index.remove(&guid);
            self.index_types.remove(&guid);
            self.index_enums.remove(&guid);
            self.symbol_rvas.remove(&guid);
            self.symbol_addresses.remove(&guid);
            self.source_lines.remove(&guid);
            self.index_diagnostics.remove(&guid);
            self.type_cache
                .retain(|(cached_guid, _), _| *cached_guid != guid);
            self.enum_cache
                .retain(|(cached_guid, _), _| *cached_guid != guid);
            self.locals_cache
                .retain(|(cached_guid, _), _| *cached_guid != guid);
        }
    }

    pub fn retain_modules_for_dtb(&self, dtb: Dtb, live_modules: &[ModuleInfo]) -> usize {
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
        let removed = module_keys.len();
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
        removed
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

    pub fn module_pdb_identity(&self, dtb: Dtb, base_address: VirtAddr) -> Option<PdbIdentity> {
        let module = self.modules.get(&Self::module_key(dtb, base_address))?;
        let age = *self.pdb_ages.get(&module.guid)?;
        Some(PdbIdentity {
            guid: module.guid,
            age,
        })
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

    pub fn has_guid(&self, guid: u128) -> bool {
        self.pdbs.contains_key(&guid)
    }

    pub fn has_matching_pdb(&self, job: &DownloadJob) -> bool {
        job.matches_loaded_identity(&self.pdb_ages)
    }
}

/// Anchored glob match: `*` matches any number of bytes, `?` exactly one.
/// `ignore_case` compares literals ASCII case-insensitively (symbol, type,
/// process, and module names); pool tags are case-sensitive.
pub fn glob_matches(pattern: &str, name: &str, ignore_case: bool) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let mut pattern_index = 0;
    let mut name_index = 0;
    let mut star_index = None;
    let mut star_name_index = 0;

    while name_index < name.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?'
                || pattern[pattern_index] == name[name_index]
                || (ignore_case && pattern[pattern_index].eq_ignore_ascii_case(&name[name_index])))
        {
            pattern_index += 1;
            name_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_name_index = name_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_name_index += 1;
            name_index = star_name_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

mod cache;
mod discovery;
pub mod download;
mod index;
mod index_build;
mod locals;
mod lookup;
mod source;
mod types;

use cache::{ModuleIdentities, symbols_directory};
pub use index::SymbolIndex;

#[cfg(test)]
mod tests;
