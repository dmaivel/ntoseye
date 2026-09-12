use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{ModuleInfo, WinObject, read_pe_header_page},
    memory,
    types::{Arch, Dtb, PhysAddr, VirtAddr},
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
use spin::{Mutex, RwLock};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, OnceLock, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};
use std::{
    fmt,
    io::{self, Cursor, Write},
};

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
    index_build_results: DashMap<u128, Arc<OnceLock<std::result::Result<(), String>>>>,
    index: DashMap<u128, SymbolIndex>,
    index_types: DashMap<u128, SymbolIndex>,
    index_enums: DashMap<u128, SymbolIndex>,
    /// GUID -> symbol name -> every address-bearing PDB record. Private/static
    /// duplicates retain their compiland identity; resolution prefers public
    /// records when present but never collapses distinct candidate addresses.
    symbol_rvas: DashMap<u128, HashMap<String, Vec<IndexedSymbol>>>,
    source_lines: DashMap<u128, Vec<SourceLineEntry>>,
    index_diagnostics: DashMap<u128, Vec<SymbolIndexDiagnostic>>,

    /// (guid, struct name) -> parsed layout. `dump_struct_with_types`
    /// otherwise rescans the entire PDB type stream on every call; keying on
    /// guid makes this self-coherent (a reloaded module gets a new guid, so a
    /// stale entry can never be returned).
    type_cache: DashMap<(u128, String), Arc<TypeInfo>>,

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

    /// PDBs of modules identified in earlier sessions; opened on first use so
    /// building a store touches no files.
    identities: OnceLock<ModuleIdentities>,
}

fn guid_to_u128(guid: GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.Data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.Data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.Data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.Data4);
    u128::from_be_bytes(bytes)
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

fn symbol_sources_from_servers(servers: &[String]) -> Vec<SymbolSource> {
    let mut sources = Vec::with_capacity(servers.len() + 1);
    sources.push(SymbolSource::Cache);
    sources.extend(servers.iter().cloned().map(SymbolSource::Http));
    sources
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureLocal {
    pub name: String,
    pub type_name: String,
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

/// The image identity the symbol server keys on: file name, `TimeDateStamp`,
/// `SizeOfImage`. The loader's module record carries all three.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModuleIdentity {
    name: String,
    time_date_stamp: u32,
    size_of_image: u32,
}

impl ModuleIdentity {
    fn of(module: &ModuleInfo) -> Option<Self> {
        Some(Self {
            name: SymbolStore::symbol_server_file_name(&module.name).to_ascii_lowercase(),
            time_date_stamp: module.time_date_stamp?,
            size_of_image: module.size,
        })
    }
}

/// What [`SymbolStore::build_download_job`] needs to name a PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PdbReference {
    server_name: String,
    guid: u128,
    age: u32,
}

/// Module identity to PDB map persisted across sessions, one tab-separated
/// line per module, so a module seen before is identified without reading
/// its headers, debug directory, and CodeView record from the target.
struct ModuleIdentities {
    path: Option<PathBuf>,
    entries: std::sync::Mutex<HashMap<ModuleIdentity, PdbReference>>,
}

impl ModuleIdentities {
    fn open(path: Option<PathBuf>) -> Self {
        let entries = path
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| text.lines().filter_map(Self::parse_line).collect())
            .unwrap_or_default();
        Self {
            path,
            entries: std::sync::Mutex::new(entries),
        }
    }

    fn parse_line(line: &str) -> Option<(ModuleIdentity, PdbReference)> {
        let mut fields = line.split('\t');
        let name = fields.next()?.to_string();
        let time_date_stamp = u32::from_str_radix(fields.next()?, 16).ok()?;
        let size_of_image = u32::from_str_radix(fields.next()?, 16).ok()?;
        let guid = u128::from_str_radix(fields.next()?, 16).ok()?;
        let age = u32::from_str_radix(fields.next()?, 16).ok()?;
        let server_name = fields.next()?.to_string();
        if fields.next().is_some() || name.is_empty() || server_name.is_empty() {
            return None;
        }
        Some((
            ModuleIdentity {
                name,
                time_date_stamp,
                size_of_image,
            },
            PdbReference {
                server_name,
                guid,
                age,
            },
        ))
    }

    fn format_line(identity: &ModuleIdentity, reference: &PdbReference) -> String {
        format!(
            "{}\t{:08x}\t{:x}\t{:032X}\t{:X}\t{}\n",
            identity.name,
            identity.time_date_stamp,
            identity.size_of_image,
            reference.guid,
            reference.age,
            reference.server_name
        )
    }

    fn get(&self, identity: &ModuleIdentity) -> Option<PdbReference> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity)
            .cloned()
    }

    /// Record a module's PDB. A failure to persist only costs the next
    /// session the reads this one already paid.
    fn insert(&self, identity: ModuleIdentity, reference: PdbReference) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.get(&identity) == Some(&reference) {
            return;
        }
        let line = Self::format_line(&identity, &reference);
        let replaced = entries.insert(identity, reference).is_some();
        if let Some(path) = &self.path {
            let _ = if replaced {
                Self::write_all(path, &entries)
            } else {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut file| file.write_all(line.as_bytes()))
            };
        }
    }

    /// Drop a module whose recorded PDB could not be loaded.
    fn remove(&self, identity: &ModuleIdentity) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.remove(identity).is_some()
            && let Some(path) = &self.path
        {
            let _ = Self::write_all(path, &entries);
        }
    }

    fn write_all(path: &Path, entries: &HashMap<ModuleIdentity, PdbReference>) -> io::Result<()> {
        let text: String = entries
            .iter()
            .map(|(identity, reference)| Self::format_line(identity, reference))
            .collect();
        std::fs::write(path, text)
    }
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

    fn identity(name: &str) -> ModuleIdentity {
        ModuleIdentity {
            name: name.to_string(),
            time_date_stamp: 0x6600_0000,
            size_of_image: 0x7000,
        }
    }

    fn reference(age: u32) -> PdbReference {
        PdbReference {
            server_name: "driver.pdb".to_string(),
            guid: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
            age,
        }
    }

    /// Identities survive a reopen, a re-recorded module keeps one entry,
    /// and a forgotten one stays forgotten; a damaged line is skipped
    /// rather than poisoning the rest.
    #[test]
    fn module_identities_persist_across_reopen() {
        let root = temp_root("identities");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("identities");

        let identities = ModuleIdentities::open(Some(path.clone()));
        identities.insert(identity("a.sys"), reference(1));
        identities.insert(identity("b.sys"), reference(2));
        identities.insert(identity("a.sys"), reference(3));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"garbage line\n")
            .unwrap();

        let reopened = ModuleIdentities::open(Some(path.clone()));
        assert_eq!(reopened.get(&identity("a.sys")), Some(reference(3)));
        assert_eq!(reopened.get(&identity("b.sys")), Some(reference(2)));
        assert_eq!(reopened.get(&identity("c.sys")), None);

        reopened.remove(&identity("a.sys"));
        let again = ModuleIdentities::open(Some(path));
        assert_eq!(again.get(&identity("a.sys")), None);
        assert_eq!(again.get(&identity("b.sys")), Some(reference(2)));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A module recorded in an earlier session is identified without a
    /// single read from the target.
    #[test]
    fn remembered_module_is_discovered_without_reading_the_target() {
        struct NoReads;
        impl MemoryOps<PhysAddr> for NoReads {
            fn read_bytes(&self, addr: PhysAddr, _: &mut [u8]) -> Result<()> {
                panic!("read at {addr:#x} for a remembered module");
            }
            fn write_bytes(&self, _: PhysAddr, _: &[u8]) -> Result<()> {
                unreachable!()
            }
        }

        let root = temp_root("identity-discovery");
        std::fs::create_dir_all(&root).unwrap();
        let store = SymbolStore::new();
        let identities = ModuleIdentities::open(Some(root.join("identities")));
        identities.insert(identity("driver.sys"), reference(2));
        store.identities.set(identities).ok().unwrap();

        let mut module = ModuleInfo::new(
            "\\SystemRoot\\drivers\\Driver.sys".to_string(),
            VirtAddr(0xffff_f800_1000_0000),
            0x7000,
        );
        module = module.with_time_date_stamp(0x6600_0000);
        let discovery = store
            .extract_download_job(&NoReads, 0x1000, &module, Arch::Amd64)
            .unwrap();
        let ModuleSymbolDiscovery::Ready { job, guid, source } = discovery else {
            panic!("expected a ready job");
        };
        assert!(matches!(source, ModuleSymbolSource::Identity));
        assert_eq!(guid, reference(2).guid);
        assert_eq!(job.filename, "driver.pdb");
        assert!(
            job.urls[0].ends_with("/driver.pdb/0123456789ABCDEF0123456789ABCDEF2/driver.pdb"),
            "{}",
            job.urls[0]
        );
        let _ = std::fs::remove_dir_all(root);
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

    #[test]
    fn local_source_paths_cover_direct_and_symbol_store_layouts() {
        let identity = PdbIdentity {
            guid: 0x00112233445566778899AABBCCDDEEFF,
            age: 2,
        };
        let root = Path::new("/symbols");

        assert_eq!(
            local_source_candidates(root, "private.pdb", identity),
            vec![
                root.join("private.pdb"),
                root.join("private.pdb")
                    .join("00112233445566778899AABBCCDDEEFF2")
                    .join("private.pdb")
            ]
        );
    }

    #[test]
    fn pdb_identity_requires_guid_and_non_stale_age() {
        let expected = PdbIdentity {
            guid: 0x1234,
            age: 3,
        };
        assert!(expected.matches(expected).is_ok());
        assert!(
            expected
                .matches(PdbIdentity {
                    guid: expected.guid,
                    age: 4
                })
                .is_ok()
        );
        assert!(
            expected
                .matches(PdbIdentity {
                    guid: 0x5678,
                    age: 3
                })
                .unwrap_err()
                .contains("GUID mismatch")
        );
        assert!(
            expected
                .matches(PdbIdentity {
                    guid: expected.guid,
                    age: 2
                })
                .unwrap_err()
                .contains("age mismatch")
        );
    }

    #[test]
    fn duplicate_private_symbols_remain_candidates_while_public_symbols_take_precedence() {
        let mut symbols = HashMap::new();
        insert_symbol_rva(
            &mut symbols,
            "duplicate".to_string(),
            0x100,
            SymbolVisibility::Private,
            Some("first.obj".to_string()),
        );
        insert_symbol_rva(
            &mut symbols,
            "duplicate".to_string(),
            0x200,
            SymbolVisibility::Private,
            Some("second.obj".to_string()),
        );
        assert_eq!(preferred_symbol_records(&symbols["duplicate"]).len(), 2);

        insert_symbol_rva(
            &mut symbols,
            "duplicate".to_string(),
            0x300,
            SymbolVisibility::Public,
            None,
        );
        let preferred = preferred_symbol_records(&symbols["duplicate"]);
        assert_eq!(preferred.len(), 1);
        assert_eq!(preferred[0].rva, 0x300);
        assert_eq!(symbols["duplicate"].len(), 3);
    }

    #[test]
    fn symbol_resolution_reports_distinct_private_candidates() {
        let store = SymbolStore::new();
        let dtb = 0x1000_u64;
        let base = VirtAddr(0x0000_0001_8000_0000);
        store.modules.insert(
            SymbolStore::module_key(dtb, base),
            LoadedModule {
                name: "driver.sys".to_string(),
                guid: 1,
                base_address: base,
                size: 0x1000,
                dtb,
            },
        );
        store.symbol_rvas.insert(
            1,
            HashMap::from([(
                "worker".to_string(),
                vec![
                    IndexedSymbol {
                        rva: 0x100,
                        visibility: SymbolVisibility::Private,
                        compiland: Some("first.obj".to_string()),
                    },
                    IndexedSymbol {
                        rva: 0x200,
                        visibility: SymbolVisibility::Private,
                        compiland: Some("second.obj".to_string()),
                    },
                ],
            )]),
        );

        let candidates = store.find_symbol_candidates(dtb, "driver!worker");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].compiland.as_deref(), Some("first.obj"));
        assert_eq!(candidates[1].address, base + 0x200_u64);
        let error = store
            .find_symbol_with_module(dtb, "driver!worker")
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("driver!worker"));
        assert!(message.contains("first.obj"));
        assert!(message.contains("second.obj"));
    }

    #[test]
    fn public_symbol_is_the_unique_resolution_for_a_duplicate_name() {
        let store = SymbolStore::new();
        let dtb = 0x1000_u64;
        let base = VirtAddr(0x0000_0001_8000_0000);
        store.modules.insert(
            SymbolStore::module_key(dtb, base),
            LoadedModule {
                name: "driver.sys".to_string(),
                guid: 1,
                base_address: base,
                size: 0x1000,
                dtb,
            },
        );
        store.symbol_rvas.insert(
            1,
            HashMap::from([(
                "worker".to_string(),
                vec![
                    IndexedSymbol {
                        rva: 0x100,
                        visibility: SymbolVisibility::Private,
                        compiland: Some("first.obj".to_string()),
                    },
                    IndexedSymbol {
                        rva: 0x300,
                        visibility: SymbolVisibility::Public,
                        compiland: None,
                    },
                ],
            )]),
        );

        assert_eq!(
            store.find_symbol_with_module(dtb, "driver!worker").unwrap(),
            Some((base + 0x300_u64, "driver".to_string()))
        );
    }

    #[test]
    fn source_line_lookup_obeys_line_ranges() {
        let lines = vec![
            SourceLineEntry {
                rva: 0x100,
                length: Some(4),
                location: SourceLocation {
                    file: "private.c".to_string(),
                    line: 10,
                    column: Some(2),
                    local_path: None,
                    local_exists: false,
                },
            },
            SourceLineEntry {
                rva: 0x110,
                length: None,
                location: SourceLocation {
                    file: "private.c".to_string(),
                    line: 11,
                    column: None,
                    local_path: None,
                    local_exists: false,
                },
            },
            SourceLineEntry {
                rva: 0x120,
                length: Some(2),
                location: SourceLocation {
                    file: "private.c".to_string(),
                    line: 12,
                    column: None,
                    local_path: None,
                    local_exists: false,
                },
            },
        ];

        assert_eq!(lookup_source_line(&lines, 0x102).unwrap().line, 10);
        assert!(lookup_source_line(&lines, 0x104).is_none());
        assert_eq!(lookup_source_line(&lines, 0x11f).unwrap().line, 11);
        assert!(lookup_source_line(&lines, 0x122).is_none());
    }

    #[test]
    fn definition_range_excludes_gaps() {
        let gaps = [(4, 2)];
        assert!(live_range_contains(0x100, 10, &gaps, 0x103));
        assert!(!live_range_contains(0x100, 10, &gaps, 0x104));
        assert!(!live_range_contains(0x100, 10, &gaps, 0x105));
        assert!(live_range_contains(0x100, 10, &gaps, 0x106));
        assert!(!live_range_contains(0x100, 10, &gaps, 0x10a));
    }

    #[test]
    fn source_file_matching_supports_windows_paths_and_basenames() {
        assert!(source_file_matches(
            r"C:\agent\src\private.c",
            r"c:\AGENT\src\PRIVATE.c"
        ));
        assert!(source_file_matches(r"C:\agent\src\private.c", "PRIVATE.c"));
        assert!(!source_file_matches(r"C:\agent\src\private.c", "other.c"));
    }

    #[test]
    fn source_path_remapping_prefers_existing_ordered_candidate() {
        let root = temp_root("source-remap");
        let first = root.join("missing");
        let second = root.join("checkout");
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(second.join("private.c"), "int private;\n").unwrap();
        let mappings = vec![
            SourcePathMapping {
                recorded_prefix: Some(r"C:\agent\src".to_string()),
                local_root: first,
            },
            SourcePathMapping {
                recorded_prefix: Some(r"C:\agent\src".to_string()),
                local_root: second.clone(),
            },
        ];

        let (candidate, exists) = remap_source_file(r"C:\agent\src\private.c", &mappings);
        assert!(exists);
        assert_eq!(candidate, Some(second.join("private.c")));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn source_path_remapping_rejects_traversal_and_symlink_escape() {
        let root = temp_root("source-containment");
        let checkout = root.join("checkout");
        let outside = root.join("outside");
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.c"), "secret\n").unwrap();
        std::os::unix::fs::symlink(&outside, checkout.join("link")).unwrap();
        let mappings = [SourcePathMapping {
            recorded_prefix: Some(r"C:\agent\src".to_string()),
            local_root: checkout.clone(),
        }];

        assert_eq!(
            remap_source_file(r"C:\agent\src\..\outside\secret.c", &mappings),
            (None, false)
        );
        let (candidate, exists) = remap_source_file(r"C:\agent\src\link\secret.c", &mappings);
        assert_eq!(candidate, Some(checkout.join("link/secret.c")));
        assert!(!exists);
        assert_eq!(remap_source_file("/etc/passwd", &[]), (None, false));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn source_addresses_resolve_cached_file_and_line() {
        let store = SymbolStore::new();
        let guid = 0x55;
        let dtb = 0x1000;
        store.modules.insert(
            (dtb, 0x140000000),
            LoadedModule {
                name: "private.exe".to_string(),
                guid,
                base_address: VirtAddr(0x140000000),
                size: 0x1000,
                dtb,
            },
        );
        store.source_lines.insert(
            guid,
            vec![
                SourceLineEntry {
                    rva: 0x120,
                    length: Some(4),
                    location: SourceLocation {
                        file: r"C:\agent\src\private.c".to_string(),
                        line: 42,
                        column: None,
                        local_path: None,
                        local_exists: false,
                    },
                },
                SourceLineEntry {
                    rva: 0x180,
                    length: Some(4),
                    location: SourceLocation {
                        file: r"C:\agent\src\private.c".to_string(),
                        line: 42,
                        column: None,
                        local_path: None,
                        local_exists: false,
                    },
                },
            ],
        );
        store.set_source_paths(vec![SourcePathMapping {
            recorded_prefix: Some(r"C:\agent\src".to_string()),
            local_root: "/checkout".into(),
        }]);

        assert_eq!(
            store.source_addresses(dtb, "private.c", 42),
            vec![VirtAddr(0x140000120), VirtAddr(0x140000180)]
        );
        assert_eq!(
            store.source_addresses(dtb, "/checkout/private.c", 42),
            vec![VirtAddr(0x140000120), VirtAddr(0x140000180)]
        );
    }

    #[test]
    fn invalidating_module_clears_registration_and_status() {
        let store = SymbolStore::new();
        let dtb = 0x1000;
        let base = VirtAddr(0x180000000);
        store.modules.insert(
            (dtb, base.0),
            LoadedModule {
                name: "reload.dll".to_string(),
                guid: 0x99,
                base_address: base,
                size: 0x1000,
                dtb,
            },
        );
        store.set_module_symbol_status(dtb, base, ModuleSymbolStatus::Loaded);

        store.invalidate_modules(dtb, &[base]);

        assert!(store.find_module_for_address(dtb, base).is_none());
        assert!(store.module_symbol_status(dtb, base).is_none());
    }

    #[test]
    fn module_lookup_prefers_active_dtb_then_falls_back() {
        let store = SymbolStore::new();
        let active_dtb = 0x1000;
        let fallback_dtb = 0x2000;
        let base = VirtAddr(0x180000000);
        let module = |name: &str, guid, dtb| LoadedModule {
            name: name.to_string(),
            guid,
            base_address: base,
            size: 0x1000,
            dtb,
        };
        store.modules.insert(
            (fallback_dtb, base.0),
            module("kernel.sys", 0x22, fallback_dtb),
        );

        let resolved = store
            .find_module_for_address_in_context(active_dtb, fallback_dtb, base)
            .unwrap();
        assert_eq!(resolved.dtb, fallback_dtb);
        assert_eq!(resolved.name, "kernel.sys");

        store
            .modules
            .insert((active_dtb, base.0), module("user.dll", 0x11, active_dtb));
        let resolved = store
            .find_module_for_address_in_context(active_dtb, fallback_dtb, base)
            .unwrap();
        assert_eq!(resolved.dtb, active_dtb);
        assert_eq!(resolved.name, "user.dll");
    }
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
            guid: self.guid,
            base_address: self.module.base_address,
            size: self.module.size,
            dtb: self.dtb,
        }
    }
}

impl DownloadJob {
    pub fn needs_download(&self) -> bool {
        self.pdb.is_some() || !self.path.exists() || *FORCE_DOWNLOADS.get_or_init(|| false)
    }

    fn matches_loaded_identity(&self, ages: &DashMap<u128, u32>) -> bool {
        self.pdb.as_ref().is_some_and(|request| {
            ages.get(&request.identity.guid)
                .is_some_and(|age| *age >= request.identity.age)
        })
    }

    fn expected_identity(&self) -> Option<PdbIdentity> {
        self.pdb.as_ref().map(|request| request.identity)
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
    if let Some(request) = &job.pdb {
        return resolve_pdb_job(job, request, pb);
    }
    if !job.needs_download() {
        return Ok(());
    }

    let mut last_err = None;
    for url in &job.urls {
        match download_url_to_path(url, &job.path, &job.filename, &pb) {
            Ok(()) => {
                pb.finish_and_clear();
                return Ok(());
            }
            Err(error) => last_err = Some(error),
        }
    }
    pb.finish_and_clear();
    Err(last_err
        .unwrap_or_else(|| Error::DebugInfo("no symbol server URL to download from".into())))
}

fn download_url_to_path(url: &str, path: &Path, filename: &str, pb: &ProgressBar) -> Result<()> {
    let response = reqwest::blocking::get(url)?;
    let response = response.error_for_status()?;
    let total_size = response.content_length().unwrap_or(0);

    pb.set_style(download_progress_style()?);
    pb.set_length(total_size);
    pb.set_message(format_progress_name(filename));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Rename into place: truncating the final path would corrupt concurrent
    // jobs and any existing mmap of it.
    let tmp_path = unique_temp_path(path);
    let mut file = File::create(&tmp_path)?;
    let mut downloaded = pb.wrap_read(response);

    let copied = std::io::copy(&mut downloaded, &mut file);
    drop(file);
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    static DOWNLOAD_SEQ: AtomicU64 = AtomicU64::new(0);
    path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        DOWNLOAD_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

fn pdb_identity(path: &Path) -> Result<PdbIdentity> {
    let file = File::open(path)?;
    let mut pdb = pdb2::PDB::open(file)?;
    let info = pdb.pdb_information()?;
    Ok(PdbIdentity {
        guid: info.guid.as_u128(),
        age: info.age,
    })
}

fn validate_pdb_identity(path: &Path, expected: PdbIdentity) -> std::result::Result<(), String> {
    let actual = pdb_identity(path).map_err(|err| format!("invalid PDB: {err}"))?;
    expected.matches(actual)
}

fn local_source_candidates(root: &Path, server_name: &str, identity: PdbIdentity) -> Vec<PathBuf> {
    vec![
        root.join(server_name),
        root.join(server_name)
            .join(identity.symbol_store_key())
            .join(server_name),
    ]
}

fn install_local_pdb(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = unique_temp_path(destination);
    if let Err(err) = std::fs::copy(source, &tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }
    std::fs::rename(tmp_path, destination)?;
    Ok(())
}

fn resolve_pdb_job(job: &DownloadJob, request: &PdbRequest, pb: ProgressBar) -> Result<()> {
    let mut attempts = Vec::new();
    let mut seen_paths = HashSet::new();
    let force = *FORCE_DOWNLOADS.get_or_init(|| false);

    for source in &request.sources {
        match source {
            SymbolSource::Cache => {
                if force {
                    attempts.push(format!("{}: skipped by force-download", source));
                    continue;
                }
                let candidates = std::iter::once(job.path.clone()).chain(
                    job.path.parent().into_iter().flat_map(|root| {
                        local_source_candidates(root, &request.server_name, request.identity)
                    }),
                );
                for candidate in candidates {
                    if !seen_paths.insert(candidate.clone()) {
                        continue;
                    }
                    if !candidate.is_file() {
                        attempts.push(format!("{}: not found", candidate.display()));
                        continue;
                    }
                    match validate_pdb_identity(&candidate, request.identity) {
                        Ok(()) => {
                            install_local_pdb(&candidate, &job.path)?;
                            return Ok(());
                        }
                        Err(reason) => {
                            attempts.push(format!("{}: {}", candidate.display(), reason))
                        }
                    }
                }
            }
            SymbolSource::LocalDirectory(root) => {
                for candidate in
                    local_source_candidates(root, &request.server_name, request.identity)
                {
                    if !seen_paths.insert(candidate.clone()) {
                        continue;
                    }
                    if !candidate.is_file() {
                        attempts.push(format!("{}: not found", candidate.display()));
                        continue;
                    }
                    match validate_pdb_identity(&candidate, request.identity) {
                        Ok(()) => {
                            install_local_pdb(&candidate, &job.path)?;
                            return Ok(());
                        }
                        Err(reason) => {
                            attempts.push(format!("{}: {}", candidate.display(), reason))
                        }
                    }
                }
            }
            SymbolSource::Http(root) => {
                let url = format!(
                    "{}/{}/{}/{}",
                    root.trim_end_matches('/'),
                    request.server_name,
                    request.identity.symbol_store_key(),
                    request.server_name
                );
                let tmp_path = unique_temp_path(&job.path);
                match download_url_to_path(&url, &tmp_path, &job.filename, &pb) {
                    Ok(()) => match validate_pdb_identity(&tmp_path, request.identity) {
                        Ok(()) => {
                            if let Some(parent) = job.path.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::rename(&tmp_path, &job.path)?;
                            pb.finish_and_clear();
                            return Ok(());
                        }
                        Err(reason) => {
                            let _ = std::fs::remove_file(&tmp_path);
                            attempts.push(format!("{}: {}", url, reason));
                        }
                    },
                    Err(err) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        attempts.push(format!("{}: {}", url, err));
                    }
                }
            }
        }
    }

    pb.finish_and_clear();
    Err(Error::DebugInfo(format!(
        "no matching PDB found; attempted {}",
        attempts.join("; ")
    )))
}

pub fn download_jobs_parallel(jobs: Vec<DownloadJob>) -> Vec<Result<PathBuf>> {
    let mp = Arc::new(MultiProgress::new());

    jobs.into_par_iter()
        .map(|job| {
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

fn insert_symbol_rva(
    rvas: &mut HashMap<String, Vec<IndexedSymbol>>,
    name: String,
    rva: u32,
    visibility: SymbolVisibility,
    compiland: Option<String>,
) {
    let records = rvas.entry(name).or_default();
    if records.iter().any(|record| {
        record.rva == rva && record.visibility == visibility && record.compiland == compiland
    }) {
        return;
    }
    records.push(IndexedSymbol {
        rva,
        visibility,
        compiland,
    });
}

fn preferred_symbol_records(records: &[IndexedSymbol]) -> Vec<&IndexedSymbol> {
    let has_public = records
        .iter()
        .any(|record| record.visibility == SymbolVisibility::Public);
    records
        .iter()
        .filter(|record| !has_public || record.visibility == SymbolVisibility::Public)
        .collect()
}

fn record_index_diagnostic(
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
    phase: &'static str,
    compiland: Option<&str>,
    message: impl Into<String>,
) {
    const DIAGNOSTIC_LIMIT: usize = 64;
    if diagnostics.len() < DIAGNOSTIC_LIMIT {
        diagnostics.push(SymbolIndexDiagnostic {
            phase,
            compiland: compiland.map(str::to_string),
            message: message.into(),
        });
    }
}

fn lookup_source_line(lines: &[SourceLineEntry], rva: u32) -> Option<SourceLocation> {
    let index = lines
        .partition_point(|line| line.rva <= rva)
        .checked_sub(1)?;
    let line = &lines[index];
    let covered = match line.length {
        Some(length) => rva < line.rva.saturating_add(length),
        None => lines.get(index + 1).is_some_and(|next| rva < next.rva) || rva == line.rva,
    };
    covered.then(|| line.location.clone())
}

fn source_file_matches(recorded: &str, query: &str) -> bool {
    let recorded = recorded.replace('\\', "/");
    let query = query.replace('\\', "/");
    if query.contains('/') {
        recorded.eq_ignore_ascii_case(&query)
    } else {
        recorded
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(&query))
    }
}

#[cfg(test)]
fn live_range_contains(start_rva: u32, length: u16, gaps: &[(u16, u16)], target_rva: u32) -> bool {
    let Some(relative) = target_rva.checked_sub(start_rva) else {
        return false;
    };
    relative < u32::from(length)
        && !gaps.iter().any(|(start, length)| {
            relative >= u32::from(*start)
                && relative < u32::from(*start).saturating_add(u32::from(*length))
        })
}

fn pdb_register_name(register: pdb2::Register, cpu: Option<pdb2::CPUType>) -> String {
    let Some(cpu) = cpu else {
        return format!("cvreg{}", register.0);
    };
    let Ok(register) = pdb2::register::Register::new(register, cpu) else {
        return format!("cvreg{}", register.0);
    };
    let display = register.to_string();
    display
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or(&display)
        .to_ascii_lowercase()
}

fn pdb_live_range_contains(
    range: &pdb2::AddressRange,
    gaps: &[pdb2::AddressGap],
    address_map: &pdb2::AddressMap,
    target_rva: u32,
) -> bool {
    let Some(start) = range.offset.to_rva(address_map) else {
        return false;
    };
    let Some(relative) = target_rva.checked_sub(start.0) else {
        return false;
    };
    relative < u32::from(range.cb_range)
        && !gaps.iter().any(|gap| {
            relative >= u32::from(gap.gap_start_offset)
                && relative
                    < u32::from(gap.gap_start_offset).saturating_add(u32::from(gap.cb_range))
        })
}

fn safe_source_relative_path(relative: &str) -> Option<PathBuf> {
    let mut path = PathBuf::new();
    for component in relative
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if matches!(component, "." | "..") || component.contains(':') {
            return None;
        }
        path.push(component);
    }
    (!path.as_os_str().is_empty()).then_some(path)
}

fn source_candidate_is_contained_file(root: &Path, candidate: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let Ok(candidate) = candidate.canonicalize() else {
        return false;
    };
    candidate.is_file() && candidate.starts_with(root)
}

fn remap_source_file(recorded: &str, mappings: &[SourcePathMapping]) -> (Option<PathBuf>, bool) {
    let normalized = recorded.replace('\\', "/");
    let lowered = normalized.to_ascii_lowercase();
    let mut first_candidate = None;
    for mapping in mappings {
        let relative = match &mapping.recorded_prefix {
            Some(prefix) => {
                let prefix = prefix.replace('\\', "/");
                let prefix_lower = prefix.to_ascii_lowercase();
                if !lowered.starts_with(&prefix_lower)
                    || (normalized.len() != prefix.len()
                        && normalized.as_bytes().get(prefix.len()) != Some(&b'/'))
                {
                    continue;
                }
                normalized[prefix.len()..].trim_start_matches('/')
            }
            None => normalized.rsplit('/').next().unwrap_or(&normalized),
        };
        let Some(relative) = safe_source_relative_path(relative) else {
            continue;
        };
        let candidate = mapping.local_root.join(relative);
        if first_candidate.is_none() {
            first_candidate = Some(candidate.clone());
        }
        if source_candidate_is_contained_file(&mapping.local_root, &candidate) {
            return (Some(candidate), true);
        }
    }
    (first_candidate, false)
}

// CodeView kinds consumed by the private address index. pdb2 keeps these
// constants private, so keep the upstream S_* names beside their wire values.
fn is_private_address_symbol_kind(kind: u16) -> bool {
    matches!(
        kind,
        0x1007 // S_LDATA32_ST
            | 0x1008 // S_GDATA32_ST
            | 0x100a // S_LPROC32_ST
            | 0x100b // S_GPROC32_ST
            | 0x1020 // S_LMANDATA_ST
            | 0x1021 // S_GMANDATA_ST
            | 0x110c // S_LDATA32
            | 0x110d // S_GDATA32
            | 0x110f // S_LPROC32
            | 0x1110 // S_GPROC32
            | 0x111c // S_LMANDATA
            | 0x111d // S_GMANDATA
            | 0x1146 // S_LPROC32_ID
            | 0x1147 // S_GPROC32_ID
            | 0x1155 // S_LPROC32_DPC
            | 0x1156 // S_LPROC32_DPC_ID
    )
}

// pdb2 0.10.1 debug-asserts on valid Windows S_CALLEES/S_CALLERS records whose
// optional invocation-count tail is longer than the function list. Neither
// record contributes addresses or local-variable state, so never parse them.
const PDB_S_CALLEES: u16 = 0x115a;
const PDB_S_CALLERS: u16 = 0x115b;

fn is_pdb2_function_list_symbol(kind: u16) -> bool {
    matches!(kind, PDB_S_CALLEES | PDB_S_CALLERS)
}
/// Largest `IMAGE_DEBUG_DIRECTORY` array read from a guest image; real images
/// carry a few entries.
const MAX_DEBUG_DIRECTORY_BYTES: usize = 0x1000;
/// Largest CodeView record read from a guest image (a GUID, an age, and a
/// PDB path).
const MAX_CODEVIEW_BYTES: usize = 0x1000;

impl SymbolStore {
    fn module_key(dtb: Dtb, base_address: VirtAddr) -> (Dtb, u64) {
        (dtb, base_address.0)
    }

    pub fn new() -> Self {
        Self {
            pdbs: DashMap::new(),
            mmaps: DashMap::new(),
            pdb_ages: DashMap::new(),
            index_build_results: DashMap::new(),
            index: DashMap::new(),
            index_types: DashMap::new(),
            index_enums: DashMap::new(),
            symbol_rvas: DashMap::new(),
            source_lines: DashMap::new(),
            index_diagnostics: DashMap::new(),
            type_cache: DashMap::new(),
            modules: DashMap::new(),
            module_status: DashMap::new(),
            module_source: DashMap::new(),
            sources: RwLock::new(Self::default_symbol_sources()),
            source_paths: RwLock::new(Vec::new()),
            kernel_guid: Mutex::new(None),
            identities: OnceLock::new(),
        }
    }

    pub fn index_diagnostics(&self, guid: u128) -> Vec<SymbolIndexDiagnostic> {
        self.index_diagnostics
            .get(&guid)
            .map(|diagnostics| diagnostics.clone())
            .unwrap_or_default()
    }

    fn default_symbol_sources() -> Vec<SymbolSource> {
        symbol_sources_from_servers(pdb_servers())
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
        *self.sources.write() = Self::default_symbol_sources();
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
    pub fn set_kernel_guid(&self, guid: Option<u128>) {
        *self.kernel_guid.lock() = guid;
    }

    pub fn kernel_guid(&self) -> Option<u128> {
        *self.kernel_guid.lock()
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
                .insert((guid, type_info.name.clone()), Arc::new(type_info));
        }
        self.symbol_rvas.insert(
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
            self.source_lines.remove(&guid);
            self.index_diagnostics.remove(&guid);
            self.type_cache
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

    fn read_debug_directory_location<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(u32, u32)>> {
        let header_buf = read_pe_header_page(base_address, memory)?;
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

        // A handful of entries at most in any real image; the field is guest
        // memory, so bound the allocation before trusting it.
        if debug_size as usize > MAX_DEBUG_DIRECTORY_BYTES {
            return Err(Error::DebugInfo(format!(
                "debug directory size {debug_size:#x} exceeds {MAX_DEBUG_DIRECTORY_BYTES:#x}"
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
        &self,
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        entry: &IMAGE_DEBUG_DIRECTORY,
    ) -> Result<(String, Option<(DownloadJob, u128)>)> {
        if entry.AddressOfRawData == 0 || entry.SizeOfData < 4 {
            return Err(Error::DebugInfo(
                "codeview entry is missing raw data".to_string(),
            ));
        }
        if entry.SizeOfData as usize > MAX_CODEVIEW_BYTES {
            return Err(Error::DebugInfo(format!(
                "codeview entry size {:#x} exceeds {MAX_CODEVIEW_BYTES:#x}",
                entry.SizeOfData
            )));
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
                let job =
                    self.build_download_job(&path, guid_to_u128(image.Signature), image.Age)?;
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
        &self,
        pdb_file_name: &str,
        guid: u128,
        age: u32,
    ) -> Result<(DownloadJob, u128)> {
        let server_name = Self::symbol_server_file_name(pdb_file_name);
        // `guid_to_u128` packs the GUID fields big-endian in field order, so
        // the hex of the u128 is the symbol server's GUID spelling.
        let guid_str = format!("{guid:032X}");

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

        let job = DownloadJob {
            urls,
            path,
            filename: format!("{}.pdb", stem),
            pdb: Some(PdbRequest {
                identity: PdbIdentity { guid, age },
                server_name: server_name.to_string(),
                sources: self.symbol_sources(),
            }),
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
            pdb: None,
        })
    }

    fn symbol_server_file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    pub fn load_from_binary(&self, object: &mut WinObject, name: &str) -> Result<Option<u128>> {
        let view = object.view().ok_or(Error::ViewFailed)?;
        if name.eq_ignore_ascii_case("ntoskrnl.exe")
            && !matches!(view.file_header().Machine, 0x8664 | 0xaa64)
        {
            return Err(Error::UnsupportedArchitecture(format!(
                "kernel image {} (machine {:#06x})",
                name,
                view.file_header().Machine
            )));
        }

        if let Some((job, guid)) =
            self.extract_download_job_from_memory(&object.memory(), object.base_address)?
        {
            download_job(&job, ProgressBar::new(0))?;
            self.ensure_pdb_loaded(job.expected_identity().unwrap(), &job.path)?;

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

        let Some((pdb_job, guid)) = self.extract_download_job_from_image_file(&image_job.path)?
        else {
            return Ok(None);
        };

        download_job(&pdb_job, ProgressBar::new(0))?;
        self.ensure_pdb_loaded(pdb_job.expected_identity().unwrap(), &pdb_job.path)?;

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

    pub fn has_matching_pdb(&self, job: &DownloadJob) -> bool {
        job.matches_loaded_identity(&self.pdb_ages)
    }

    pub fn extract_download_job<B: MemoryOps<PhysAddr>>(
        &self,
        backend: &B,
        dtb: Dtb,
        module: &ModuleInfo,
        arch: Arch,
    ) -> Result<ModuleSymbolDiscovery> {
        if let Some(reference) =
            ModuleIdentity::of(module).and_then(|identity| self.module_identities().get(&identity))
        {
            let (job, guid) =
                self.build_download_job(&reference.server_name, reference.guid, reference.age)?;
            return Ok(ModuleSymbolDiscovery::Ready {
                job,
                guid,
                source: ModuleSymbolSource::Identity,
            });
        }
        let (module_name, base_address) = (module.name.as_str(), module.base_address);
        // `dtb` is the root for the module's own VA half: the kernel root for
        // kernel modules and the process root for user modules.
        let addr_space = match arch {
            Arch::Amd64 => memory::AddressSpace::new(backend, dtb),
            Arch::Arm64 => memory::AddressSpace::new_arm64(backend, dtb, dtb),
        };
        match self.extract_download_job_from_memory(&addr_space, base_address) {
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

    fn module_identities(&self) -> &ModuleIdentities {
        self.identities.get_or_init(|| {
            ModuleIdentities::open(symbols_directory().map(|dir| dir.join("identities")))
        })
    }

    /// Record which PDB `job` names for `module`. A module whose record
    /// lacks a `TimeDateStamp` has no identity to key on.
    pub fn remember_module_identity(&self, module: &ModuleInfo, job: &DownloadJob) {
        if let (Some(identity), Some(request)) = (ModuleIdentity::of(module), &job.pdb) {
            self.module_identities().insert(
                identity,
                PdbReference {
                    server_name: request.server_name.clone(),
                    guid: request.identity.guid,
                    age: request.identity.age,
                },
            );
        }
    }

    /// Forget a recorded PDB that failed to load.
    pub fn forget_module_identity(&self, module: &ModuleInfo) {
        if let Some(identity) = ModuleIdentity::of(module) {
            self.module_identities().remove(&identity);
        }
    }

    pub fn load_downloaded_pdb(&self, load: &ModuleSymbolLoad) -> Result<()> {
        let module_key = Self::module_key(load.dtb, load.module.base_address);
        if let Some(existing) = self.modules.get(&module_key) {
            // A job that outlived a reload/reattach of its module describes a
            // different image; finishing it would mark the wrong PDB loaded.
            if existing.guid != load.guid {
                return Err(Error::DebugInfo(format!(
                    "stale symbol job for {}: module was replaced",
                    load.module.name
                )));
            }
            self.set_module_symbol_status(
                load.dtb,
                load.module.base_address,
                ModuleSymbolStatus::Loaded,
            );
            self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());
            return Ok(());
        }

        self.ensure_pdb_loaded(load.job.expected_identity().unwrap(), &load.job.path)?;
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
        &self,
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
                        let (job, guid) = self.build_download_job(
                            &pdb_path,
                            guid_to_u128(image.Signature),
                            image.Age,
                        )?;
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
        &self,
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

            let (_, job) = self.read_codeview_from_memory(memory, base_address, &entry)?;
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
        &self,
        image_path: &Path,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let file = File::open(image_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let pe = PeFile::from_bytes(&mmap[..])?;
        let debug = pe.debug()?;
        self.download_job_from_debug(&debug)
    }

    fn read_image_lookup_info<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<(u32, u32)> {
        let header_buf = read_pe_header_page(base_address, memory)?;
        let view = PeView::from_bytes(&header_buf)?;
        Ok((
            view.file_header().TimeDateStamp,
            view.optional_header().SizeOfImage,
        ))
    }

    fn ensure_index_built(&self, guid: u128) -> Result<()> {
        let state = self
            .index_build_results
            .entry(guid)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        match state.get_or_init(|| self.build_index(guid).map_err(|error| error.to_string())) {
            Ok(()) => Ok(()),
            Err(message) => Err(Error::DebugInfo(format!("PDB indexing failed: {message}"))),
        }
    }

    fn ensure_pdb_loaded(&self, expected: PdbIdentity, path: &Path) -> Result<()> {
        if let Some(age) = self.pdb_ages.get(&expected.guid) {
            let validation = expected
                .matches(PdbIdentity {
                    guid: expected.guid,
                    age: *age,
                })
                .map_err(Error::DebugInfo);
            drop(age);
            validation?;
            return self.ensure_index_built(expected.guid);
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
        let mut pdb = pdb2::PDB::open(cursor)?;
        let info = pdb.pdb_information()?;
        let actual = PdbIdentity {
            guid: info.guid.as_u128(),
            age: info.age,
        };
        expected.matches(actual).map_err(Error::DebugInfo)?;

        // One loader wins per guid; replacing an existing entry would unmap
        // pages the stored PDB's cursor still points into.
        match self.pdbs.entry(expected.guid) {
            Entry::Occupied(_) => {
                let matches = self
                    .pdb_ages
                    .get(&expected.guid)
                    .and_then(|age| {
                        expected
                            .matches(PdbIdentity {
                                guid: expected.guid,
                                age: *age,
                            })
                            .ok()
                    })
                    .is_some();
                if !matches {
                    return Err(Error::DebugInfo(
                        "a non-matching PDB won a concurrent load".to_string(),
                    ));
                }
            }
            Entry::Vacant(entry) => {
                self.mmaps.insert(expected.guid, mmap);
                self.pdb_ages.insert(expected.guid, actual.age);
                entry.insert(pdb.into());
            }
        }
        self.ensure_index_built(expected.guid)
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

    pub fn find_type_across_modules(&self, dtb: Dtb, type_name: &str) -> Option<Arc<TypeInfo>> {
        // Kernel definitions win over same-named user-mode types (e.g. ntdll).
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

    pub fn find_symbol_across_modules(
        &self,
        dtb: Dtb,
        symbol_name: &str,
    ) -> Result<Option<VirtAddr>> {
        self.find_symbol_with_module(dtb, symbol_name)
            .map(|resolved| resolved.map(|(address, _)| address))
    }

    /// Return every PDB candidate for a symbol, retaining module, visibility,
    /// and private-compiland provenance. `module!symbol` restricts the module;
    /// a bare symbol searches the active address space.
    pub fn find_symbol_candidates(&self, dtb: Dtb, symbol_name: &str) -> Vec<SymbolCandidate> {
        let (module_filter, name) = match symbol_name.split_once('!') {
            Some((module, name)) => (Some(module), name),
            None => (None, symbol_name),
        };
        let mut candidates = Vec::new();
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
            for record in self.symbol_records(module.guid, name) {
                candidates.push(SymbolCandidate {
                    module: short.clone(),
                    address: module.base_address + u64::from(record.rva),
                    visibility: record.visibility,
                    compiland: record.compiland,
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.module
                .to_ascii_lowercase()
                .cmp(&right.module.to_ascii_lowercase())
                .then_with(|| left.address.0.cmp(&right.address.0))
                .then_with(|| left.compiland.cmp(&right.compiland))
        });
        candidates
    }

    /// Resolve one unambiguous symbol and retain its module for display.
    pub fn find_symbol_with_module(
        &self,
        dtb: Dtb,
        symbol_name: &str,
    ) -> Result<Option<(VirtAddr, String)>> {
        let candidates = self.find_symbol_candidates(dtb, symbol_name);
        let unique_locations: HashSet<(String, u64)> = candidates
            .iter()
            .map(|candidate| (candidate.module.to_ascii_lowercase(), candidate.address.0))
            .collect();
        if unique_locations.is_empty() {
            return Ok(None);
        }
        if unique_locations.len() == 1 {
            let candidate = &candidates[0];
            return Ok(Some((candidate.address, candidate.module.clone())));
        }

        let display_name = symbol_name
            .rsplit_once('!')
            .map(|(_, name)| name)
            .unwrap_or(symbol_name);
        let labels = candidates
            .iter()
            .map(|candidate| {
                let visibility = match candidate.visibility {
                    SymbolVisibility::Public => "public".to_string(),
                    SymbolVisibility::Private => candidate
                        .compiland
                        .as_deref()
                        .map(|compiland| format!("private in {compiland}"))
                        .unwrap_or_else(|| "private".to_string()),
                };
                format!(
                    "{}!{} at {:#x} ({visibility})",
                    candidate.module, display_name, candidate.address.0
                )
            })
            .collect();
        Err(Error::AmbiguousSymbol {
            name: symbol_name.to_string(),
            candidates: labels,
        })
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

    /// Resolve the module containing `address`, preferring the active address
    /// space and then consulting an explicit fallback such as the kernel DTB.
    pub fn find_module_for_address_in_context(
        &self,
        primary_dtb: Dtb,
        fallback_dtb: Dtb,
        address: VirtAddr,
    ) -> Option<LoadedModule> {
        self.find_module_for_address(primary_dtb, address)
            .or_else(|| {
                (fallback_dtb != primary_dtb)
                    .then(|| self.find_module_for_address(fallback_dtb, address))
                    .flatten()
            })
    }

    /// Resolve a virtual address to cached C13 source information.
    pub fn source_location(&self, dtb: Dtb, address: VirtAddr) -> Option<SourceLocation> {
        let module = self.find_module_for_address(dtb, address)?;
        let rva = u32::try_from(address.0.checked_sub(module.base_address.0)?).ok()?;
        let lines = self.source_lines.get(&module.guid)?;
        let mut location = lookup_source_line(&lines, rva)?;
        let (local_path, local_exists) =
            remap_source_file(&location.file, &self.source_paths.read());
        location.local_path = local_path;
        location.local_exists = local_exists;
        Some(location)
    }

    /// Resolve a PDB source file and line to every loaded address in the
    /// selected address space. A bare filename matches any recorded basename;
    /// a path matches the full recorded path case-insensitively.
    pub fn source_addresses(&self, dtb: Dtb, file: &str, line: u32) -> Vec<VirtAddr> {
        let mut addresses = Vec::new();
        let mappings = self.source_paths.read();
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            let Some(lines) = self.source_lines.get(&module.guid) else {
                continue;
            };
            addresses.extend(
                lines
                    .iter()
                    .filter(|entry| {
                        if entry.location.line != line {
                            return false;
                        }
                        if source_file_matches(&entry.location.file, file) {
                            return true;
                        }
                        remap_source_file(&entry.location.file, &mappings)
                            .0
                            .is_some_and(|candidate| {
                                candidate.to_string_lossy().eq_ignore_ascii_case(file)
                            })
                    })
                    .map(|entry| module.base_address + u64::from(entry.rva)),
            );
        }
        addresses.sort_by_key(|address| address.0);
        addresses.dedup();
        addresses
    }

    fn procedure_local(
        &self,
        finder: &TypeFinder<'_>,
        name: String,
        type_index: TypeIndex,
        is_parameter: bool,
        location: LocalVariableLocation,
    ) -> ProcedureLocal {
        ProcedureLocal {
            name,
            type_name: self
                .resolve_type(finder, type_index)
                .map(|parsed| parsed.to_string())
                .unwrap_or_else(|_| format!("type({:#x})", type_index.0)),
            byte_size: self.type_size(finder, type_index, 8).ok(),
            is_parameter,
            location,
        }
    }

    /// Return locals and parameters belonging to the procedure that covers
    /// `address`. Definition ranges are filtered against the requested RVA and
    /// gaps. Unsupported DIA recipes and split locations remain explicit
    /// `Unavailable` entries rather than guessed values.
    pub fn procedure_locals(
        &self,
        dtb: Dtb,
        address: VirtAddr,
    ) -> Result<Option<Vec<ProcedureLocal>>> {
        let Some(module) = self.find_module_for_address(dtb, address) else {
            return Ok(None);
        };
        let Some(relative) = address.0.checked_sub(module.base_address.0) else {
            return Ok(None);
        };
        let Ok(target_rva) = u32::try_from(relative) else {
            return Ok(None);
        };
        let Some(pdb) = self.pdbs.get_mut(&module.guid) else {
            return Ok(None);
        };
        let mut pdb_lock = pdb.lock();
        let address_map = pdb_lock.address_map()?;

        let type_information = pdb_lock.type_information()?;
        let mut finder = type_information.finder();
        let mut types = type_information.iter();
        while types.next()?.is_some() {
            finder.update(&types);
        }

        let debug_information = pdb_lock.debug_information()?;
        let mut modules = debug_information.modules()?;
        while let Some(dbi_module) = modules.next()? {
            let Some(module_info) = pdb_lock.module_info(&dbi_module)? else {
                continue;
            };
            let mut symbols = module_info.symbols()?;

            let mut procedure_end = None;
            let mut block_scopes: Vec<(pdb2::SymbolIndex, bool)> = Vec::new();
            let mut locals = Vec::new();
            let mut current_local = None;
            let mut current_optimized_out = false;
            let mut cpu_type = None;

            while let Some(symbol) = symbols.next()? {
                if let Some(end) = procedure_end {
                    if symbol.index() == end {
                        return Ok(Some(locals));
                    }
                    while block_scopes
                        .last()
                        .is_some_and(|(block_end, _)| *block_end == symbol.index())
                    {
                        block_scopes.pop();
                    }
                }

                if is_pdb2_function_list_symbol(symbol.raw_kind()) {
                    continue;
                }
                let data = symbol.parse()?;
                if let pdb2::SymbolData::CompileFlags(compile) = &data {
                    cpu_type = Some(compile.cpu_type);
                }
                if procedure_end.is_none() {
                    let pdb2::SymbolData::Procedure(procedure) = data else {
                        continue;
                    };
                    let Some(start) = procedure.offset.to_rva(&address_map) else {
                        continue;
                    };
                    if target_rva >= start.0 && target_rva < start.0.saturating_add(procedure.len) {
                        procedure_end = Some(procedure.end);
                    }
                    continue;
                }

                let visible = block_scopes.iter().all(|(_, contains)| *contains);
                match data {
                    pdb2::SymbolData::Block(block) => {
                        let contains = block.offset.to_rva(&address_map).is_some_and(|start| {
                            target_rva >= start.0 && target_rva < start.0.saturating_add(block.len)
                        });
                        block_scopes.push((block.end, contains));
                        current_local = None;
                    }
                    pdb2::SymbolData::Local(local) if visible => {
                        current_optimized_out = local.flags.isoptimizedout;
                        let reason = if current_optimized_out {
                            "optimized out"
                        } else {
                            "not live at this address"
                        };
                        locals.push(self.procedure_local(
                            &finder,
                            local.name.to_string().into(),
                            local.type_index,
                            local.flags.isparam,
                            LocalVariableLocation::Unavailable {
                                reason: reason.to_string(),
                            },
                        ));
                        current_local = Some(locals.len() - 1);
                    }
                    pdb2::SymbolData::Local(_) => {
                        current_local = None;
                        current_optimized_out = false;
                    }
                    pdb2::SymbolData::DefRangeRegister(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        let location = if range.flags.maybe {
                            LocalVariableLocation::Unavailable {
                                reason: format!(
                                    "conditionally available in {}",
                                    pdb_register_name(range.register, cpu_type)
                                ),
                            }
                        } else {
                            LocalVariableLocation::Register {
                                register: pdb_register_name(range.register, cpu_type),
                            }
                        };
                        locals[current_local.unwrap()].location = location;
                    }
                    pdb2::SymbolData::DefRangeRegisterRelative(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            if range.spilled_udt_member == 0 && range.offset_parent == 0 {
                                LocalVariableLocation::RegisterRelative {
                                    register: pdb_register_name(range.base_register, cpu_type),
                                    offset: range.offset_base_pointer,
                                }
                            } else {
                                LocalVariableLocation::Unavailable {
                                    reason: "split register-relative location".to_string(),
                                }
                            };
                    }
                    pdb2::SymbolData::DefRangeFramePointerRelative(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::FrameRelative {
                                offset: range.offset,
                            };
                    }
                    pdb2::SymbolData::DefRangeFramePointerRelativeFullScope(range)
                        if !current_optimized_out && current_local.is_some() =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::FrameRelative {
                                offset: range.offset,
                            };
                    }
                    pdb2::SymbolData::DefRange(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: format!(
                                    "unsupported DIA location program {}",
                                    range.program
                                ),
                            };
                    }
                    pdb2::SymbolData::DefRangeSubField(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: "split subfield location".to_string(),
                            };
                    }
                    pdb2::SymbolData::DefRangeSubFieldRegister(range)
                        if !current_optimized_out
                            && current_local.is_some()
                            && pdb_live_range_contains(
                                &range.range,
                                &range.gaps,
                                &address_map,
                                target_rva,
                            ) =>
                    {
                        locals[current_local.unwrap()].location =
                            LocalVariableLocation::Unavailable {
                                reason: "split subfield register location".to_string(),
                            };
                    }
                    pdb2::SymbolData::RegisterVariable(variable) if visible => {
                        locals.push(self.procedure_local(
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::Register {
                                register: pdb_register_name(variable.register, cpu_type),
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::RegisterRelative(variable) if visible => {
                        locals.push(self.procedure_local(
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::RegisterRelative {
                                register: pdb_register_name(variable.register, cpu_type),
                                offset: variable.offset,
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::BasePointerRelative(variable) if visible => {
                        locals.push(self.procedure_local(
                            &finder,
                            variable.name.to_string().into(),
                            variable.type_index,
                            variable.slot.is_some(),
                            LocalVariableLocation::FrameRelative {
                                offset: variable.offset,
                            },
                        ));
                        current_local = None;
                    }
                    pdb2::SymbolData::MultiRegisterVariable(variable) if visible => {
                        if let Some((_, name)) = variable.registers.first() {
                            locals.push(self.procedure_local(
                                &finder,
                                name.to_string().into(),
                                variable.type_index,
                                false,
                                LocalVariableLocation::Unavailable {
                                    reason: "value spans multiple registers".to_string(),
                                },
                            ));
                        }
                        current_local = None;
                    }
                    _ => {}
                }
            }
        }
        Ok(None)
    }

    fn build_index(&self, guid: u128) -> Result<()> {
        let pdb = self.pdbs.get_mut(&guid).ok_or(Error::ExpectedSymbols)?;
        let mut pdb_lock = pdb.lock();
        let address_map = pdb_lock.address_map()?;
        let mut diagnostics = Vec::new();
        let string_table = match pdb_lock.string_table() {
            Ok(table) => Some(table),
            Err(error) => {
                record_index_diagnostic(
                    &mut diagnostics,
                    "source strings",
                    None,
                    error.to_string(),
                );
                None
            }
        };

        let mut strings = Vec::new();
        let mut rvas: HashMap<String, Vec<IndexedSymbol>> = HashMap::new();
        let mut source_lines = Vec::new();

        // Module streams contain private procedures and addressable data that
        // are absent from the global public stream. SymbolData::Local records
        // are deliberately ignored: stack locals are not global symbols.
        match pdb_lock.debug_information() {
            Ok(debug_information) => match debug_information.modules() {
                Ok(mut modules) => loop {
                    let module = match modules.next() {
                        Ok(Some(module)) => module,
                        Ok(None) => break,
                        Err(error) => {
                            record_index_diagnostic(
                                &mut diagnostics,
                                "module iteration",
                                None,
                                error.to_string(),
                            );
                            break;
                        }
                    };
                    let compiland = module.module_name().into_owned();
                    let module_info = match pdb_lock.module_info(&module) {
                        Ok(Some(module_info)) => module_info,
                        Ok(None) => {
                            record_index_diagnostic(
                                &mut diagnostics,
                                "module info",
                                Some(&compiland),
                                "module information is absent",
                            );
                            continue;
                        }
                        Err(error) => {
                            record_index_diagnostic(
                                &mut diagnostics,
                                "module info",
                                Some(&compiland),
                                error.to_string(),
                            );
                            continue;
                        }
                    };

                    match module_info.symbols() {
                        Ok(mut module_symbols) => loop {
                            let symbol = match module_symbols.next() {
                                Ok(Some(symbol)) => symbol,
                                Ok(None) => break,
                                Err(error) => {
                                    record_index_diagnostic(
                                        &mut diagnostics,
                                        "private symbol iteration",
                                        Some(&compiland),
                                        error.to_string(),
                                    );
                                    break;
                                }
                            };
                            if !is_private_address_symbol_kind(symbol.raw_kind()) {
                                continue;
                            }
                            let data = match symbol.parse() {
                                Ok(data) => data,
                                Err(error) => {
                                    record_index_diagnostic(
                                        &mut diagnostics,
                                        "private symbol record",
                                        Some(&compiland),
                                        format!("kind {:#06x}: {error}", symbol.raw_kind()),
                                    );
                                    continue;
                                }
                            };
                            let named_offset: Option<(String, pdb2::PdbInternalSectionOffset)> =
                                match data {
                                    pdb2::SymbolData::Procedure(procedure) => {
                                        Some((procedure.name.to_string().into(), procedure.offset))
                                    }
                                    pdb2::SymbolData::Data(data) => {
                                        Some((data.name.to_string().into(), data.offset))
                                    }
                                    _ => None,
                                };
                            if let Some((name, offset)) = named_offset
                                && let Some(rva) = offset.to_rva(&address_map)
                            {
                                insert_symbol_rva(
                                    &mut rvas,
                                    name.clone(),
                                    rva.0,
                                    SymbolVisibility::Private,
                                    Some(compiland.clone()),
                                );
                                strings.push(name);
                            }
                        },
                        Err(error) => record_index_diagnostic(
                            &mut diagnostics,
                            "private symbol stream",
                            Some(&compiland),
                            error.to_string(),
                        ),
                    }

                    let Some(strings_table) = string_table.as_ref() else {
                        continue;
                    };
                    let line_program = match module_info.line_program() {
                        Ok(line_program) => line_program,
                        Err(error) => {
                            record_index_diagnostic(
                                &mut diagnostics,
                                "line program",
                                Some(&compiland),
                                error.to_string(),
                            );
                            continue;
                        }
                    };
                    let mut lines = line_program.lines();
                    loop {
                        // pdb2 0.10.1 asserts while bounding some valid
                        // non-monotonic C13 line records. Isolate that module,
                        // but retain an explicit diagnostic rather than silently
                        // truncating all remaining source information.
                        let next =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lines.next()));
                        let line = match next {
                            Ok(Ok(Some(line))) => line,
                            Ok(Ok(None)) => break,
                            Ok(Err(error)) => {
                                record_index_diagnostic(
                                    &mut diagnostics,
                                    "line iteration",
                                    Some(&compiland),
                                    error.to_string(),
                                );
                                break;
                            }
                            Err(payload) => {
                                let message = payload
                                    .downcast_ref::<&str>()
                                    .map(|message| (*message).to_string())
                                    .or_else(|| payload.downcast_ref::<String>().cloned())
                                    .unwrap_or_else(|| "pdb2 line iterator panicked".to_string());
                                record_index_diagnostic(
                                    &mut diagnostics,
                                    "line iteration",
                                    Some(&compiland),
                                    message,
                                );
                                break;
                            }
                        };
                        let Some(rva) = line.offset.to_rva(&address_map) else {
                            continue;
                        };
                        let file_info = match line_program.get_file_info(line.file_index) {
                            Ok(file_info) => file_info,
                            Err(error) => {
                                record_index_diagnostic(
                                    &mut diagnostics,
                                    "source file",
                                    Some(&compiland),
                                    error.to_string(),
                                );
                                continue;
                            }
                        };
                        let file = match strings_table.get(file_info.name) {
                            Ok(file) => file,
                            Err(error) => {
                                record_index_diagnostic(
                                    &mut diagnostics,
                                    "source string",
                                    Some(&compiland),
                                    error.to_string(),
                                );
                                continue;
                            }
                        };
                        source_lines.push(SourceLineEntry {
                            rva: rva.0,
                            length: line.length,
                            location: SourceLocation {
                                file: file.to_string().into(),
                                line: line.line_start,
                                column: line.column_start.filter(|column| *column != 0),
                                local_path: None,
                                local_exists: false,
                            },
                        });
                    }
                },
                Err(error) => record_index_diagnostic(
                    &mut diagnostics,
                    "module list",
                    None,
                    error.to_string(),
                ),
            },
            Err(error) => record_index_diagnostic(
                &mut diagnostics,
                "debug information",
                None,
                error.to_string(),
            ),
        }

        // Public records have intentional precedence over duplicate private
        // names, regardless of module stream order.
        let symbol_table = pdb_lock.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb2::SymbolData::Public(data)) => {
                    let name: String = data.name.to_string().into();
                    if let Some(rva) = data.offset.to_rva(&address_map) {
                        insert_symbol_rva(
                            &mut rvas,
                            name.clone(),
                            rva.0,
                            SymbolVisibility::Public,
                            None,
                        );
                    }
                    strings.push(name);
                }
                Ok(_) => {}
                Err(error) => record_index_diagnostic(
                    &mut diagnostics,
                    "public symbol record",
                    None,
                    format!("kind {:#06x}: {error}", symbol.raw_kind()),
                ),
            }
        }

        strings.sort();
        strings.dedup();
        source_lines.sort_by_key(|line| line.rva);

        let mut type_strings: Vec<String> = Vec::new();
        let mut enum_strings: Vec<String> = Vec::new();

        let type_information = pdb_lock.type_information()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next()? {
            type_finder.update(&iter);

            match typ.parse() {
                Ok(type_data) => match type_data {
                    TypeData::Class(class)
                        if !class.properties.forward_reference()
                            && class.name.to_string() != "<anonymous-tag>" =>
                    {
                        type_strings.push(class.name.to_string().into());
                    }
                    TypeData::Union(union)
                        if !union.properties.forward_reference()
                            && union.name.to_string() != "<anonymous-tag>" =>
                    {
                        type_strings.push(union.name.to_string().into());
                    }
                    TypeData::Enumeration(en)
                        if !en.properties.forward_reference()
                            && en.name.to_string() != "<anonymous-tag>" =>
                    {
                        enum_strings.push(en.name.to_string().into());
                    }
                    _ => {}
                },
                Err(error) => record_index_diagnostic(
                    &mut diagnostics,
                    "type record",
                    None,
                    error.to_string(),
                ),
            }
        }

        type_strings.sort();
        type_strings.dedup();
        enum_strings.sort();
        enum_strings.dedup();

        // Publish every derived index together only after all mandatory PDB
        // streams have been parsed. A fatal type/public stream error must not
        // leave a partially indexed PDB that later lookups mistake for success.
        self.index.insert(guid, SymbolIndex { names: strings });
        self.symbol_rvas.insert(guid, rvas);
        self.source_lines.insert(guid, source_lines);
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

        self.index_diagnostics.insert(guid, diagnostics);
        Ok(())
    }

    fn symbol_records(&self, guid: u128, symbol_name: &str) -> Vec<IndexedSymbol> {
        if let Some(map) = self.symbol_rvas.get(&guid) {
            return map
                .get(symbol_name)
                .map(|records| {
                    preferred_symbol_records(records)
                        .into_iter()
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
        }

        // Before indexing completes, the global stream can still provide public
        // records. Private candidates become available when `build_index` runs.
        let Some(pdb) = self.pdbs.get_mut(&guid) else {
            return Vec::new();
        };
        let mut pdb_lock = pdb.lock();
        let Ok(symbol_table) = pdb_lock.global_symbols() else {
            return Vec::new();
        };
        let Ok(address_map) = pdb_lock.address_map() else {
            return Vec::new();
        };
        let mut symbols = symbol_table.iter();
        let mut records = Vec::new();
        while let Ok(Some(symbol)) = symbols.next() {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse()
                && data.name.to_string() == symbol_name
                && let Some(rva) = data.offset.to_rva(&address_map)
            {
                records.push(IndexedSymbol {
                    rva: rva.0,
                    visibility: SymbolVisibility::Public,
                    compiland: None,
                });
            }
        }
        records
    }

    pub fn symbol_rva<S>(&self, guid: u128, symbol_name: S) -> Result<Option<u32>>
    where
        S: AsRef<str>,
    {
        let symbol_name = symbol_name.as_ref();
        let records = self.symbol_records(guid, symbol_name);
        let mut rvas: Vec<u32> = records.iter().map(|record| record.rva).collect();
        rvas.sort_unstable();
        rvas.dedup();
        match rvas.as_slice() {
            [] => Ok(None),
            [rva] => Ok(Some(*rva)),
            _ => Err(Error::AmbiguousSymbol {
                name: symbol_name.to_string(),
                candidates: records
                    .iter()
                    .map(|record| {
                        let provenance = record
                            .compiland
                            .as_deref()
                            .map(|compiland| format!(" in {compiland}"))
                            .unwrap_or_default();
                        format!("RVA {:#x}{provenance}", record.rva)
                    })
                    .collect(),
            }),
        }
    }

    pub fn closest_symbol(
        &self,
        guid: u128,
        base_address: VirtAddr,
        address: VirtAddr,
    ) -> Option<(String, u32)> {
        let target_rva = u32::try_from(address.0.checked_sub(base_address.0)?).ok()?;
        let symbols = self.symbol_rvas.get(&guid)?;
        symbols
            .iter()
            .flat_map(|(name, records)| {
                records.iter().filter_map(move |record| {
                    target_rva
                        .checked_sub(record.rva)
                        .filter(|offset| *offset <= 8192)
                        .map(|offset| (name, offset, record.visibility, &record.compiland))
                })
            })
            .min_by(|left, right| {
                left.1
                    .cmp(&right.1)
                    .then_with(|| {
                        let rank = |visibility| match visibility {
                            SymbolVisibility::Public => 0,
                            SymbolVisibility::Private => 1,
                        };
                        rank(left.2).cmp(&rank(right.2))
                    })
                    .then_with(|| left.0.cmp(right.0))
                    .then_with(|| left.3.cmp(right.3))
            })
            .map(|(name, offset, _, _)| (name.clone(), offset))
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
                // pdb2 reports cumulative byte sizes per dimension (`int[4][4]`
                // is `[16, 64]`), so the last entry is the whole array.
                Ok(data.dimensions.last().map_or(0, |&bytes| u64::from(bytes)))
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
                // Total byte size (see `type_size`) over the element size gives
                // the flattened element count.
                let bytes = data.dimensions.last().copied().unwrap_or(0);
                let sizeof_type = (self.type_size(finder, data.element_type, 8)? as u32).max(1);
                Ok(ParsedType::Array(Box::new(inner), bytes / sizeof_type))
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

    pub fn dump_struct_with_types<S>(&self, guid: u128, struct_name: S) -> Option<Arc<TypeInfo>>
    where
        S: Into<String> + AsRef<str>,
    {
        // A hit skips the full PDB type-stream scan below. Cloning the cached
        // layout is cheap next to that scan, so callers keep their owned return
        let cache_key = (guid, struct_name.as_ref().to_string());
        if let Some(cached) = self.type_cache.get(&cache_key) {
            return Some(Arc::clone(&cached));
        }

        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            let (name, size, field_index) = match typ.parse() {
                Ok(TypeData::Class(class)) if !class.properties.forward_reference() => {
                    (class.name.to_string(), class.size, class.fields)
                }
                Ok(TypeData::Union(union)) if !union.properties.forward_reference() => {
                    (union.name.to_string(), union.size, Some(union.fields))
                }
                _ => continue,
            };
            if name != struct_name.as_ref() {
                continue;
            }

            let mut fields_map: HashMap<String, FieldInfo> = HashMap::new();
            if let Some(field_index) = field_index {
                self.process_field_list(&type_finder, field_index, &mut fields_map)
                    .ok()?;
            }

            let type_info = TypeInfo {
                name: struct_name.into(),
                size: size as usize,
                fields: fields_map,
            };
            let type_info = Arc::new(type_info);
            self.type_cache.insert(cache_key, Arc::clone(&type_info));
            return Some(type_info);
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

        // Per-keystroke hot path over up to hundreds of thousands of names.
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

        // Partial-select the top `limit`; ties break alphabetically.
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
