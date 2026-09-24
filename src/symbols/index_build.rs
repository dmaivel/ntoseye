//! Building a PDB's searchable indexes: parsing its symbol, line, and type
//! streams under the PDB lock, then publishing the derived indexes.

use super::{
    AddressEntry, IndexedSymbol, SourceLineEntry, SourceLocation, SymbolIndex,
    SymbolIndexDiagnostic, SymbolStore, SymbolVisibility,
};
use crate::error::{Error, Result};
use pdb2::{AddressMap, FallibleIterator, StringTable, TypeData, TypeIndex};
use std::{
    collections::HashMap,
    io::Cursor,
    sync::{Arc, OnceLock},
};

/// Everything one PDB contributes to the symbol store, parsed while the PDB is
/// locked so that building the searchable indexes from it (which is parallel)
/// runs with no lock held.
struct ParsedIndexData {
    strings: Vec<String>,
    rvas: HashMap<String, Vec<IndexedSymbol>>,
    source_lines: Vec<SourceLineEntry>,
    type_strings: Vec<String>,
    enum_strings: Vec<String>,
    struct_defs: HashMap<String, (u64, TypeIndex)>,
    diagnostics: Vec<SymbolIndexDiagnostic>,
}

/// The C name under an x86 public symbol's calling-convention decoration:
/// `_name` (cdecl), `_name@N` (stdcall), `@name@N` (fastcall). C++ names
/// (`?...`) are left as they are, as on x64, where C names are undecorated.
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

pub(super) fn insert_symbol_rva(
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

fn address_index(rvas: &HashMap<String, Vec<IndexedSymbol>>) -> Vec<AddressEntry> {
    let rank = |visibility| match visibility {
        SymbolVisibility::Public => 0u8,
        SymbolVisibility::Private => 1,
    };
    let mut entries: Vec<(u32, u8, &String, &Option<String>)> = rvas
        .iter()
        .flat_map(|(name, records)| {
            records
                .iter()
                .map(move |record| (record.rva, rank(record.visibility), name, &record.compiland))
        })
        .collect();
    entries.sort_unstable();
    entries
        .into_iter()
        .map(|(rva, _, name, _)| AddressEntry {
            rva,
            name: name.clone(),
        })
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

    /// Parse every index input out of the PDB for `guid`.
    ///
    /// The `pdbs` shard guard and the PDB mutex are held for exactly this
    /// call. See [`Self::build_index`] for why they must not outlive it.
    fn parse_index_data(&self, guid: u128) -> Result<ParsedIndexData> {
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
        parse_module_streams(
            &mut pdb_lock,
            &address_map,
            string_table.as_ref(),
            &mut strings,
            &mut rvas,
            &mut source_lines,
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
            &mut diagnostics,
        )?;

        strings.sort();
        strings.dedup();
        source_lines.sort_by_key(|line| line.rva);

        let mut type_strings: Vec<String> = Vec::new();
        let mut enum_strings: Vec<String> = Vec::new();
        let mut struct_defs: HashMap<String, (u64, TypeIndex)> = HashMap::new();
        parse_type_stream(
            &mut pdb_lock,
            &mut type_strings,
            &mut enum_strings,
            &mut struct_defs,
            &mut diagnostics,
        )?;

        type_strings.sort();
        type_strings.dedup();
        enum_strings.sort();
        enum_strings.dedup();

        Ok(ParsedIndexData {
            strings,
            rvas,
            source_lines,
            type_strings,
            enum_strings,
            struct_defs,
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
    fn build_index(&self, guid: u128) -> Result<()> {
        let parsed = self.parse_index_data(guid)?;

        // Publish every derived index together only after all mandatory PDB
        // streams have been parsed. A fatal type/public stream error must not
        // leave a partially indexed PDB that later lookups mistake for success.
        self.index
            .insert(guid, SymbolIndex::from_names(parsed.strings));
        self.publish_symbol_rvas(guid, parsed.rvas);
        self.source_lines.insert(guid, parsed.source_lines);
        self.index_types
            .insert(guid, SymbolIndex::from_names(parsed.type_strings));
        self.index_enums
            .insert(guid, SymbolIndex::from_names(parsed.enum_strings));
        self.struct_defs.insert(guid, parsed.struct_defs);
        self.index_diagnostics.insert(guid, parsed.diagnostics);
        Ok(())
    }

    pub(super) fn publish_symbol_rvas(
        &self,
        guid: u128,
        rvas: HashMap<String, Vec<IndexedSymbol>>,
    ) {
        self.symbol_addresses.insert(guid, address_index(&rvas));
        self.symbol_rvas.insert(guid, rvas);
    }
}

/// Private procedures and addressable data from every module stream, and the
/// C13 source lines of each module.
fn parse_module_streams(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
    address_map: &AddressMap<'_>,
    string_table: Option<&StringTable<'_>>,
    strings: &mut Vec<String>,
    rvas: &mut HashMap<String, Vec<IndexedSymbol>>,
    source_lines: &mut Vec<SourceLineEntry>,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) {
    match pdb.debug_information() {
        Ok(debug_information) => match debug_information.modules() {
            Ok(mut modules) => loop {
                let module = match modules.next() {
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
                    Ok(None) => {
                        record_index_diagnostic(
                            diagnostics,
                            "module info",
                            Some(&compiland),
                            "module information is absent",
                        );
                        continue;
                    }
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
                            && let Some(rva) = offset.to_rva(address_map)
                        {
                            insert_symbol_rva(
                                rvas,
                                name.clone(),
                                rva.0,
                                SymbolVisibility::Private,
                                Some(compiland.clone()),
                            );
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
            Err(error) => {
                record_index_diagnostic(diagnostics, "module list", None, error.to_string())
            }
        },
        Err(error) => {
            record_index_diagnostic(diagnostics, "debug information", None, error.to_string())
        }
    }
}

/// Public symbols from the global symbol stream, undecorated when `x86`.
fn parse_public_symbols(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
    address_map: &AddressMap<'_>,
    x86: bool,
    strings: &mut Vec<String>,
    rvas: &mut HashMap<String, Vec<IndexedSymbol>>,
    diagnostics: &mut Vec<SymbolIndexDiagnostic>,
) -> Result<()> {
    let symbol_table = pdb.global_symbols()?;
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb2::SymbolData::Public(data)) => {
                let name: String = if x86 {
                    undecorate_x86(&data.name.to_string()).to_string()
                } else {
                    data.name.to_string().into()
                };
                if let Some(rva) = data.offset.to_rva(address_map) {
                    insert_symbol_rva(rvas, name.clone(), rva.0, SymbolVisibility::Public, None);
                }
                strings.push(name);
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

/// Named structs, unions, and enums from the type stream, keeping each
/// struct's largest complete definition in `struct_defs`.
fn parse_type_stream(
    pdb: &mut pdb2::PDB<'static, Cursor<&'static [u8]>>,
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
                    let name = class.name.to_string().into_owned();
                    record_struct(name.clone(), class.size, class.fields);
                    type_strings.push(name);
                }
                TypeData::Union(union)
                    if !union.properties.forward_reference()
                        && union.name.to_string() != "<anonymous-tag>" =>
                {
                    let name = union.name.to_string().into_owned();
                    record_struct(name.clone(), union.size, Some(union.fields));
                    type_strings.push(name);
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
