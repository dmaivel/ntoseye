//! Building a PDB's searchable indexes: parsing its symbol, line, and type
//! streams under the PDB lock, then publishing the derived indexes.

use std::borrow::Cow;

use super::{
    AddressEntry, DataTypes, IndexedSymbol, LoadedModule, ProcedureSpan, SourceChecksum,
    SourceLineEntry, SourceLocation, SymbolIndex, SymbolIndexDiagnostic, SymbolRvas, SymbolStore,
    SymbolVisibility, source::recorded_checksum,
};
use crate::base::error::{Error, Result};
use crate::base::types::Dtb;
use crate::nt::guest::ModuleInfo;
use crate::nt::layout::aggregate_key;
use crate::nt::pe::ModuleExportInfo;
use crate::nt::wpp::{MessageKey, TmfMessage};
use dashmap::mapref::entry::Entry;
use pdb2::{AddressMap, FallibleIterator, StringTable, TypeData, TypeIndex};
use rayon::slice::ParallelSliceMut;
use rustc_hash::{FxHashMap, FxHasher};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    io::Cursor,
    sync::{Arc, OnceLock, atomic::Ordering},
};

/// What one PDB's symbol, line and module streams contribute to the symbol
/// store, parsed while the PDB is locked so that building the searchable
/// indexes from it (which is parallel) runs with no lock held.
struct ParsedSymbols {
    strings: Vec<String>,
    rvas: SymbolRvas,
    source_lines: Vec<SourceLineEntry>,
    procedures: Vec<ProcedureSpan>,
    sections: Vec<(u32, u32)>,
    data_types: DataTypes,
    source_checksums: FxHashMap<String, SourceChecksum>,
    wpp_messages: HashMap<MessageKey, Arc<TmfMessage>>,
    diagnostics: Vec<SymbolIndexDiagnostic>,
}

/// What one PDB's type stream contributes, parsed through a handle of its
/// own (see [`SymbolStore::build_index`]).
struct ParsedTypes {
    type_strings: Vec<String>,
    enum_strings: Vec<String>,
    struct_defs: HashMap<String, (u64, TypeIndex)>,
    diagnostics: Vec<SymbolIndexDiagnostic>,
}

/// The C name under an x86 public symbol's calling-convention decoration:
/// `_name` (cdecl), `_name@N` (stdcall), `@name@N` (fastcall). C++ names
/// (`?...`) are left to [`undecorate_cpp`], as on x64, where C names are
/// undecorated.
pub(super) fn undecorate_x86(name: &str) -> &str {
    let Some(bare) = name.strip_prefix('_').or_else(|| name.strip_prefix('@')) else {
        return name;
    };
    match bare.rsplit_once('@') {
        Some((stem, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) =>
        {
            stem
        }
        _ => bare,
    }
}

/// The name WinDbg shows for an MSVC-decorated C++ name (`?...`): the
/// qualified name without its signature (`wil::details::DebugBreak`), and
/// `` `string' `` for a string literal. ARM64EC's `$$h` marker, which the
/// demangler does not read, is dropped for a second try. Any other name, and
/// one that does not demangle, stays as it is.
pub fn undecorate_cpp(name: &str) -> Cow<'_, str> {
    if !name.starts_with('?') {
        return Cow::Borrowed(name);
    }
    if name.starts_with("??_C@") {
        return Cow::Borrowed("`string'");
    }
    let demangle = |name: &str| undname::demangle(name, undname::Flags::NAME_ONLY).ok();
    demangle(name)
        .or_else(|| {
            name.contains("$$h")
                .then(|| demangle(&name.replacen("$$h", "", 1)))
                .flatten()
        })
        .map_or(Cow::Borrowed(name), Cow::Owned)
}

/// [`undecorate_cpp`] for a name already owned, which most names keep.
fn undecorate_cpp_owned(name: String) -> String {
    if name.starts_with('?') {
        undecorate_cpp(&name).into_owned()
    } else {
        name
    }
}

pub(super) fn insert_symbol_rva(
    rvas: &mut SymbolRvas,
    name: &str,
    rva: u32,
    visibility: SymbolVisibility,
    compiland: Option<String>,
) {
    // Only a name not seen yet costs a copy of it.
    let records = match rvas.get_mut(name) {
        Some(records) => records,
        None => rvas.entry(Arc::from(name)).or_default(),
    };
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

fn address_index(rvas: &SymbolRvas) -> Vec<AddressEntry> {
    let rank = |visibility| match visibility {
        SymbolVisibility::Public => 0u8,
        SymbolVisibility::Private => 1,
    };
    let mut entries: Vec<(u32, u8, &Arc<str>, &Option<String>)> = rvas
        .iter()
        .flat_map(|(name, records)| {
            records
                .iter()
                .map(move |record| (record.rva, rank(record.visibility), name, &record.compiland))
        })
        .collect();
    // No two records of a name share an RVA, visibility and compiland (see
    // `insert_symbol_rva`), so no two entries compare equal.
    entries.par_sort_unstable();
    entries
        .into_iter()
        .map(|(rva, _, name, _)| AddressEntry {
            rva,
            name: Arc::clone(name),
        })
        .collect()
}

/// The most diagnostics one PDB's indexing keeps.
const DIAGNOSTIC_LIMIT: usize = 64;

fn record_index_diagnostic(
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
    phase: &'static str,
    compiland: Option<&str>,
    message: impl Into<String>,
) {
    if diagnostics.len() < DIAGNOSTIC_LIMIT {
        diagnostics.push(SymbolIndexDiagnostic {
            phase,
            compiland: compiland.map(str::to_string),
            message: message.into(),
        });
    }
}

/// `S_ANNOTATION`: carries WPP's `TMF:` message formats.
const S_ANNOTATION: u16 = 0x1019;

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

impl SymbolStore {
    pub(super) fn ensure_index_built(&self, guid: u128) -> Result<()> {
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

    /// Parse the symbol, line and module streams of the PDB for `guid`.
    ///
    /// The `pdbs` shard guard and the PDB mutex are held for exactly this
    /// call. See [`Self::build_index`] for why they must not outlive it.
    fn parse_symbols(&self, guid: u128) -> Result<ParsedSymbols> {
        let pdb = self.pdbs.get_mut(&guid).ok_or(Error::ExpectedSymbols)?;
        let mut pdb_lock = pdb.lock();
        let address_map = pdb_lock.address_map()?;
        let mut diagnostics = Vec::new();
        let string_table = match pdb_lock.string_table() {
            Ok(table) => Some(table),
            // A public PDB has no source-file names: nothing to report.
            Err(pdb2::Error::StreamNameNotFound) => None,
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
        let mut rvas = FxHashMap::default();
        let mut source_lines = Vec::new();
        let mut procedures = Vec::new();
        let mut data_types = DataTypes::default();
        let mut source_checksums = FxHashMap::default();
        let mut wpp_messages = HashMap::new();

        // Module streams contain private procedures and addressable data that
        // are absent from the global public stream. SymbolData::Local records
        // are deliberately ignored: stack locals are not global symbols.
        parse_module_streams(
            &mut pdb_lock,
            &address_map,
            string_table.as_ref(),
            &mut strings,
            &mut rvas,
            &mut source_lines,
            &mut procedures,
            &mut data_types,
            &mut source_checksums,
            &mut wpp_messages,
            &mut diagnostics,
        );

        // Public records have intentional precedence over duplicate private
        // names, regardless of module stream order.
        let x86 = self.pointer_size(guid) == 4;
        parse_public_symbols(
            &mut pdb_lock,
            &address_map,
            x86,
            &mut strings,
            &mut rvas,
            &mut data_types,
            &mut diagnostics,
        )?;

        Ok(ParsedSymbols {
            strings,
            rvas,
            source_lines,
            procedures,
            sections: section_ranges(&mut pdb_lock),
            data_types,
            source_checksums,
            wpp_messages,
            diagnostics,
        })
    }

    /// Build and publish every derived index for `guid`.
    ///
    /// [`SymbolIndex::from_names`] is itself parallel, and the module load that
    /// calls this (`Guest::load_module_symbols`) is a `par_iter` on the same
    /// global rayon pool. A worker that blocks in a nested parallel region
    /// steals other outer items, so holding the `pdbs` shard guard across
    /// `from_names` let a worker re-enter `get_mut` for a guid hashing to the
    /// shard it already held and park on a non-reentrant lock forever, with
    /// every other worker piling onto the same shard. Parsing therefore
    /// finishes and releases both locks before any parallel work starts.
    /// That includes sorting what it parsed, which for a large PDB's
    /// hundred thousand names took as long as parsing its public symbols.
    ///
    /// The type stream is parsed at the same time as the symbol streams,
    /// through a second `pdb2` handle on the same mapping, as reading one
    /// stream needs nothing from the other and a handle is cheap to open.
    /// The parse holding the locks runs on this thread and does no parallel
    /// work, and the other takes no lock.
    fn build_index(&self, guid: u128) -> Result<()> {
        let mmap = self
            .mmaps
            .get(&guid)
            .map(|mmap| Arc::clone(&mmap))
            .ok_or(Error::ExpectedSymbols)?;
        let (symbols, types) = rayon::join(|| self.parse_symbols(guid), || parse_types(&mmap));
        // A symbol stream's error is the one reported when both fail, as
        // the symbol streams were parsed first.
        let mut parsed = symbols?;
        let mut types = types?;
        let room = DIAGNOSTIC_LIMIT.saturating_sub(parsed.diagnostics.len());
        parsed
            .diagnostics
            .extend(types.diagnostics.into_iter().take(room));

        // Equal names are the same name, so an unstable sort orders them as
        // a stable one would. Lines and procedures sharing an RVA keep the
        // order the PDB lists them in.
        for names in [
            &mut parsed.strings,
            &mut types.type_strings,
            &mut types.enum_strings,
        ] {
            names.par_sort_unstable();
            names.dedup();
        }
        parsed.source_lines.par_sort_by_key(|line| line.rva);
        parsed.procedures.par_sort_by_key(|procedure| procedure.rva);

        // Publish every derived index together only after all mandatory PDB
        // streams have been parsed. A fatal type/public stream error must not
        // leave a partially indexed PDB that later lookups mistake for success.
        self.index
            .insert(guid, SymbolIndex::from_names(parsed.strings));
        self.publish_symbol_rvas(guid, parsed.rvas);
        self.source_lines.insert(guid, parsed.source_lines);
        self.procedures.insert(guid, parsed.procedures);
        self.sections.insert(guid, parsed.sections);
        self.data_types.insert(guid, parsed.data_types);
        self.source_checksums.insert(guid, parsed.source_checksums);
        self.index_types
            .insert(guid, SymbolIndex::from_names(types.type_strings));
        self.index_enums
            .insert(guid, SymbolIndex::from_names(types.enum_strings));
        self.struct_defs.insert(guid, types.struct_defs);
        if !parsed.wpp_messages.is_empty() {
            self.wpp_messages.insert(guid, parsed.wpp_messages);
        }
        self.index_diagnostics.insert(guid, parsed.diagnostics);
        Ok(())
    }

    pub(super) fn publish_symbol_rvas(&self, guid: u128, rvas: SymbolRvas) {
        self.symbol_addresses.insert(guid, address_index(&rvas));
        self.symbol_rvas.insert(guid, rvas);
    }

    /// Index a module's export table as its symbols and register the module
    /// in the module list: the fallback for a module whose PDB no symbol
    /// source has — a vendor driver never published — which the Windows
    /// debugger serves from the image the same way. Its frames then resolve
    /// to `module!export+offset` instead of `module+offset`. A PDB indexed
    /// later under the same identity replaces the export index.
    pub fn index_module_exports(
        &self,
        dtb: Dtb,
        module: &ModuleInfo,
        guid: u128,
        exports: &[ModuleExportInfo],
    ) {
        let module_key = Self::module_key(dtb, module.base_address);
        match self.modules.entry(module_key) {
            // Another image is registered there now: this load is stale.
            Entry::Occupied(existing) if existing.get().guid != guid => return,
            Entry::Occupied(_) => {}
            Entry::Vacant(vacant) => {
                vacant.insert(LoadedModule {
                    name: module.name.clone(),
                    short_name: module.short_name.clone(),
                    guid,
                    base_address: module.base_address,
                    size: module.size,
                    dtb,
                });
            }
        }
        // An indexed PDB is strictly more than the export table, and the
        // same image's exports may be indexed already from another root.
        if !self.symbol_rvas.contains_key(&guid) {
            // An ordinal-only export has no name to index, and a forwarder
            // no address of its own.
            self.publish_public_names(
                guid,
                exports
                    .iter()
                    .filter_map(|export| Some((export.name.as_deref()?, export.rva?))),
            );
        }
        self.load_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// The key a module's export symbols are indexed under when no PDB
    /// identity is known for it: its image's name, timestamp and size, so
    /// one image shares it across address spaces. Without a timestamp the
    /// base address stands in, as two builds may share name and size. A
    /// PDB GUID is random, so this collides with none.
    pub fn image_exports_key(module: &ModuleInfo) -> u128 {
        let mut hasher = FxHasher::default();
        module.name.to_ascii_lowercase().hash(&mut hasher);
        match module.time_date_stamp {
            Some(stamp) => stamp.hash(&mut hasher),
            None => module.base_address.0.hash(&mut hasher),
        }
        (u128::from(hasher.finish()) << 64) | u128::from(module.size)
    }

    /// Index `names` at their RVAs as public symbols of `guid`, for an image
    /// whose names come from somewhere other than a PDB.
    pub(super) fn publish_public_names<'a>(
        &self,
        guid: u128,
        names: impl IntoIterator<Item = (&'a str, u32)>,
    ) {
        let mut rvas = SymbolRvas::default();
        let mut index_names = Vec::new();
        for (name, rva) in names {
            let name = undecorate_cpp(name);
            insert_symbol_rva(&mut rvas, &name, rva, SymbolVisibility::Public, None);
            index_names.push(name.into_owned());
        }
        // The index's names are sorted and deduped, as a PDB load leaves them.
        index_names.sort_unstable();
        index_names.dedup();
        self.index
            .insert(guid, SymbolIndex::from_names(index_names));
        self.publish_symbol_rvas(guid, rvas);
    }
}

/// Private procedures and addressable data from every module stream, where
/// each procedure's record is, the C13 source lines of each module with the
/// checksums its source files were compiled from, and its WPP `TMF:`
/// annotations.
#[allow(clippy::too_many_arguments)]
fn parse_module_streams(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
    address_map: &AddressMap<'_>,
    string_table: Option<&StringTable<'_>>,
    strings: &mut Vec<String>,
    rvas: &mut SymbolRvas,
    source_lines: &mut Vec<SourceLineEntry>,
    procedures: &mut Vec<ProcedureSpan>,
    data_types: &mut DataTypes,
    source_checksums: &mut FxHashMap<String, SourceChecksum>,
    wpp_messages: &mut HashMap<MessageKey, Arc<TmfMessage>>,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) {
    match pdb.debug_information() {
        Ok(debug_information) => match debug_information
            .modules()
            .map(|modules| modules.enumerate())
        {
            Ok(mut modules) => loop {
                let (module_index, module) = match modules.next() {
                    Ok(Some(module)) => module,
                    Ok(None) => break,
                    Err(error) => {
                        record_index_diagnostic(
                            diagnostics,
                            "module iteration",
                            None,
                            error.to_string(),
                        );
                        break;
                    }
                };
                let compiland = module.module_name().into_owned();
                let module_info = match pdb.module_info(&module) {
                    Ok(Some(module_info)) => module_info,
                    // Public PDBs strip most compilands' module streams, so
                    // an absent one is the norm there, not a problem.
                    Ok(None) => continue,
                    Err(error) => {
                        record_index_diagnostic(
                            diagnostics,
                            "module info",
                            Some(&compiland),
                            error.to_string(),
                        );
                        continue;
                    }
                };

                // Index in `strings` of the procedure the module's symbols
                // are in: a TMF annotation without FUNC= belongs to it.
                let mut procedure: Option<usize> = None;
                match module_info.symbols() {
                    Ok(mut module_symbols) => loop {
                        let symbol = match module_symbols.next() {
                            Ok(Some(symbol)) => symbol,
                            Ok(None) => break,
                            Err(error) => {
                                record_index_diagnostic(
                                    diagnostics,
                                    "private symbol iteration",
                                    Some(&compiland),
                                    error.to_string(),
                                );
                                break;
                            }
                        };
                        if symbol.raw_kind() == S_ANNOTATION {
                            collect_tmf_annotation(
                                &symbol,
                                procedure.map(|index| strings[index].as_str()),
                                &compiland,
                                wpp_messages,
                                diagnostics,
                            );
                            continue;
                        }
                        if !is_private_address_symbol_kind(symbol.raw_kind()) {
                            continue;
                        }
                        let data = match symbol.parse() {
                            Ok(data) => data,
                            Err(error) => {
                                record_index_diagnostic(
                                    diagnostics,
                                    "private symbol record",
                                    Some(&compiland),
                                    format!("kind {:#06x}: {error}", symbol.raw_kind()),
                                );
                                continue;
                            }
                        };
                        let is_procedure = matches!(data, pdb2::SymbolData::Procedure(_));
                        if is_procedure {
                            procedure = None;
                        }
                        if let pdb2::SymbolData::Procedure(record) = &data
                            && let Some(rva) = record.offset.to_rva(address_map)
                        {
                            procedures.push(ProcedureSpan {
                                rva: rva.0,
                                len: record.len,
                                module: module_index,
                                record: symbol.index(),
                            });
                        }
                        let named_offset: Option<(String, pdb2::PdbInternalSectionOffset)> =
                            match data {
                                pdb2::SymbolData::Procedure(procedure) => {
                                    Some((procedure.name.to_string().into(), procedure.offset))
                                }
                                pdb2::SymbolData::Data(data) => {
                                    if let Some(rva) = data.offset.to_rva(address_map) {
                                        data_types.insert(rva.0, data.type_index);
                                    }
                                    Some((data.name.to_string().into(), data.offset))
                                }
                                _ => None,
                            };
                        if let Some((name, offset)) = named_offset
                            && let Some(rva) = offset.to_rva(address_map)
                        {
                            let name = undecorate_cpp_owned(name);
                            insert_symbol_rva(
                                rvas,
                                &name,
                                rva.0,
                                SymbolVisibility::Private,
                                Some(compiland.clone()),
                            );
                            if is_procedure {
                                procedure = Some(strings.len());
                            }
                            strings.push(name);
                        }
                    },
                    Err(error) => record_index_diagnostic(
                        diagnostics,
                        "private symbol stream",
                        Some(&compiland),
                        error.to_string(),
                    ),
                }

                let Some(strings_table) = string_table else {
                    continue;
                };
                let line_program = match module_info.line_program() {
                    Ok(line_program) => line_program,
                    Err(error) => {
                        record_index_diagnostic(
                            diagnostics,
                            "line program",
                            Some(&compiland),
                            error.to_string(),
                        );
                        continue;
                    }
                };
                // Every file the module records a checksum for, including
                // those only its inlined code's lines name (headers).
                let mut files = line_program.files();
                loop {
                    match files.next() {
                        Ok(Some(file_info)) => {
                            if let Ok(file) = strings_table.get(file_info.name)
                                && let Some(checksum) = recorded_checksum(&file_info.checksum)
                            {
                                // Most modules name the same headers, so
                                // only a file not seen yet costs a String.
                                let file = file.to_string();
                                if !source_checksums.contains_key(file.as_ref()) {
                                    source_checksums.insert(file.into_owned(), checksum);
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            record_index_diagnostic(
                                diagnostics,
                                "source file checksums",
                                Some(&compiland),
                                error.to_string(),
                            );
                            break;
                        }
                    }
                }
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
                                diagnostics,
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
                                diagnostics,
                                "line iteration",
                                Some(&compiland),
                                message,
                            );
                            break;
                        }
                    };
                    let Some(rva) = line.offset.to_rva(address_map) else {
                        continue;
                    };
                    let file_info = match line_program.get_file_info(line.file_index) {
                        Ok(file_info) => file_info,
                        Err(error) => {
                            record_index_diagnostic(
                                diagnostics,
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
                                diagnostics,
                                "source string",
                                Some(&compiland),
                                error.to_string(),
                            );
                            continue;
                        }
                    };
                    let file: String = file.to_string().into();
                    source_lines.push(SourceLineEntry {
                        rva: rva.0,
                        length: line.length,
                        location: SourceLocation {
                            file,
                            line: line.line_start,
                            column: line.column_start.filter(|column| *column != 0),
                            local: None,
                        },
                    });
                }
            },
            Err(error) => {
                record_index_diagnostic(diagnostics, "module list", None, error.to_string())
            }
        },
        Err(error) => {
            record_index_diagnostic(diagnostics, "debug information", None, error.to_string())
        }
    }
}

/// Parse an `S_ANNOTATION` whose first string is `TMF:` into `wpp_messages`;
/// other annotations are ignored. The first declaration of a message wins.
fn collect_tmf_annotation(
    symbol: &pdb2::Symbol<'_>,
    procedure: Option<&str>,
    compiland: &str,
    wpp_messages: &mut HashMap<MessageKey, Arc<TmfMessage>>,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) {
    let Ok(pdb2::SymbolData::Annotation(annotation)) = symbol.parse() else {
        return;
    };
    if annotation.strings.first().map(|s| s.as_bytes()) != Some(b"TMF:") {
        return;
    }
    let strings: Vec<_> = annotation.strings.iter().map(|s| s.to_string()).collect();
    match TmfMessage::parse(&strings, procedure) {
        Ok(message) => {
            wpp_messages
                .entry(message.key())
                .or_insert_with(|| Arc::new(message));
        }
        Err(error) => {
            record_index_diagnostic(diagnostics, "wpp annotation", Some(compiland), error)
        }
    }
}

/// Public symbols from the global symbol stream, their C++ names undecorated
/// ([`undecorate_cpp`]), and their C names too when `x86`.
fn parse_public_symbols(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
    address_map: &AddressMap<'_>,
    x86: bool,
    strings: &mut Vec<String>,
    rvas: &mut SymbolRvas,
    data_types: &mut DataTypes,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) -> Result<()> {
    let offset_limit = section_offset_limit(pdb);
    let symbol_table = pdb.global_symbols()?;
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb2::SymbolData::Public(data)) => {
                let name = data.name.to_string();
                let name = if x86 {
                    undecorate_cpp(undecorate_x86(&name)).into_owned()
                } else {
                    undecorate_cpp_owned(name.into_owned())
                };
                if data.offset.offset <= offset_limit
                    && let Some(rva) = data.offset.to_rva(address_map)
                {
                    insert_symbol_rva(rvas, &name, rva.0, SymbolVisibility::Public, None);
                }
                strings.push(name);
            }
            // A global variable's record in the global stream: its name is
            // a public symbol's too, but only this record has its type.
            Ok(pdb2::SymbolData::Data(data)) => {
                if data.offset.offset <= offset_limit
                    && let Some(rva) = data.offset.to_rva(address_map)
                {
                    data_types.entry(rva.0).or_insert(data.type_index);
                }
            }
            Ok(_) => {}
            Err(error) => record_index_diagnostic(
                diagnostics,
                "public symbol record",
                None,
                format!("kind {:#06x}: {error}", symbol.raw_kind()),
            ),
        }
    }
    Ok(())
}

/// The most a section offset in `pdb` can be: the extent of the image its
/// section headers describe, as no section reaches past it. pdb2 adds a
/// section's address and an offset without checking, and an ARM64X image's
/// PDB (mscoree.pdb on ARM64) records its `__imp_` publics at minus their
/// section's address: the sum wraps past 4 GiB, which panics where overflow
/// is checked and otherwise names the image's first bytes after imports.
pub(super) fn section_offset_limit(pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>) -> u32 {
    pdb.sections()
        .ok()
        .flatten()
        .and_then(|sections| {
            sections
                .iter()
                .map(|section| {
                    section
                        .virtual_address
                        .saturating_add(section.virtual_size.max(section.size_of_raw_data))
                })
                .max()
        })
        .unwrap_or(u32::MAX)
}

/// The image sections' RVA ranges, `[start, end)` sorted by start, from the
/// PDB's copy of the section headers; empty when the PDB has none.
fn section_ranges(pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = pdb
        .sections()
        .ok()
        .flatten()
        .map(|sections| {
            sections
                .iter()
                .map(|section| {
                    let size = section.virtual_size.max(section.size_of_raw_data);
                    (
                        section.virtual_address,
                        section.virtual_address.saturating_add(size),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    ranges.sort_unstable();
    ranges
}

/// The type stream's index inputs, read through a `pdb2` handle of its own
/// on `bytes`, the PDB's mapping.
fn parse_types(bytes: &[u8]) -> Result<ParsedTypes> {
    let mut pdb = pdb2::PDB::open(Cursor::new(bytes))?;
    let mut types = ParsedTypes {
        type_strings: Vec::new(),
        enum_strings: Vec::new(),
        struct_defs: HashMap::new(),
        diagnostics: Vec::new(),
    };
    parse_type_stream(
        &mut pdb,
        &mut types.type_strings,
        &mut types.enum_strings,
        &mut types.struct_defs,
        &mut types.diagnostics,
    )?;
    Ok(types)
}

/// Named structs, unions, and enums from the type stream, keeping each
/// struct's largest complete definition in `struct_defs`. Unnamed structs
/// and unions are defined there under their [`aggregate_key`] but not
/// listed: nobody types `<unnamed-tag>#1124`.
fn parse_type_stream<'s>(
    pdb: &mut pdb2::PDB<'s, Cursor<&'s [u8]>>,
    type_strings: &mut Vec<String>,
    enum_strings: &mut Vec<String>,
    struct_defs: &mut HashMap<String, (u64, TypeIndex)>,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) -> Result<()> {
    let mut record_struct = |name: String, size: u64, fields: Option<TypeIndex>| {
        if let Some(fields) = fields {
            let entry = struct_defs.entry(name).or_insert((0, fields));
            if size >= entry.0 {
                *entry = (size, fields);
            }
        }
    };

    let type_information = pdb.type_information()?;
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
                    let name = class.name.to_string();
                    let key = aggregate_key(&name, class.fields.map(|fields| fields.0));
                    if key == name {
                        type_strings.push(name.into_owned());
                    }
                    record_struct(key, class.size, class.fields);
                }
                TypeData::Union(union)
                    if !union.properties.forward_reference()
                        && union.name.to_string() != "<anonymous-tag>" =>
                {
                    let name = union.name.to_string();
                    let key = aggregate_key(&name, Some(union.fields.0));
                    if key == name {
                        type_strings.push(name.into_owned());
                    }
                    record_struct(key, union.size, Some(union.fields));
                }
                TypeData::Enumeration(en)
                    if !en.properties.forward_reference()
                        && en.name.to_string() != "<anonymous-tag>" =>
                {
                    enum_strings.push(en.name.to_string().into());
                }
                _ => {}
            },
            Err(error) => {
                record_index_diagnostic(diagnostics, "type record", None, error.to_string())
            }
        }
    }
    Ok(())
}
