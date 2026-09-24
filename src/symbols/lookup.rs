//! Symbol resolution across loaded modules: by name, by address, and the
//! merged completion indexes.

use super::download::task_progress_style;
use super::{
    IndexedSymbol, LoadedModule, SymbolCandidate, SymbolIndex, SymbolStore, SymbolVisibility,
    format_symbol_with_offset,
};
use crate::{
    error::{Error, Result},
    types::{Dtb, VirtAddr},
};
use dashmap::DashMap;
use indicatif::ProgressBar;
use pdb2::FallibleIterator;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use std::collections::HashSet;

pub(super) fn preferred_symbol_records(records: &[IndexedSymbol]) -> Vec<&IndexedSymbol> {
    let has_public = records
        .iter()
        .any(|record| record.visibility == SymbolVisibility::Public);
    records
        .iter()
        .filter(|record| !has_public || record.visibility == SymbolVisibility::Public)
        .collect()
}

impl SymbolStore {
    /// Module-qualified (`nt!KeBugCheckEx`) names of every symbol visible from
    /// `dtb` (all modules when `None`). Qualified so a completed or listed name
    /// resolves unambiguously even when several modules export it.
    pub fn merged_symbol_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        self.merged_index(&self.index, dtb, true, "Building symbol completions")
    }

    pub fn merged_types_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        self.merged_index(&self.index_types, dtb, false, "Building type completions")
    }

    pub fn merged_enum_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        self.merged_index(&self.index_enums, dtb, false, "Building enum completions")
    }

    /// Merge the per-module indexes in `source` that are visible from `dtb`
    /// (all modules when `None`) into one searchable index. `qualify` prefixes
    /// each name with its module's short name, which symbol completion needs
    /// so an inserted name resolves unambiguously; type and enum names merge
    /// unqualified.
    ///
    /// Every step here is per-name work over millions of names on a live
    /// kernel, run whenever the active address space changes (attach, reload),
    /// so the qualification and the sort are both parallel.
    fn merged_index(
        &self,
        source: &DashMap<u128, SymbolIndex>,
        dtb: Option<Dtb>,
        qualify: bool,
        message: &'static str,
    ) -> SymbolIndex {
        let modules: Vec<(u128, String)> = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| self.module_in_scope(module, filter_dtb)))
            .map(|module| (module.guid, module.short_name.clone()))
            .collect();
        let progress = ProgressBar::new((modules.len() + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message(message);

        let per_module: Vec<Vec<String>> = modules
            .into_par_iter()
            .map(|(guid, short)| {
                let names = match source.get(&guid) {
                    Some(index) if qualify => index
                        .names
                        .iter()
                        .map(|name| format!("{short}!{name}"))
                        .collect(),
                    Some(index) => index.names.clone(),
                    None => Vec::new(),
                };
                progress.inc(1);
                names
            })
            .collect();

        let mut all_strings: Vec<String> =
            Vec::with_capacity(per_module.iter().map(Vec::len).sum());
        for names in per_module {
            all_strings.extend(names);
        }
        all_strings.par_sort_unstable();
        all_strings.dedup();

        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex::from_names(all_strings)
    }

    pub fn find_symbol_across_modules(
        &self,
        dtb: Dtb,
        symbol_name: &str,
    ) -> Result<Option<VirtAddr>> {
        self.find_symbol_with_module(dtb, symbol_name)
            .map(|resolved| resolved.map(|(address, _)| address))
    }

    /// Base address of the module whose short name is `module_short` (WinDbg
    /// lets a bare module name stand for its base: `? nt`, `u nt+0x1000`).
    pub fn module_base_by_name(&self, dtb: Dtb, module_short: &str) -> Option<VirtAddr> {
        self.modules
            .iter()
            .find(|module| {
                self.module_in_scope(module, dtb)
                    && module.short_name.eq_ignore_ascii_case(module_short)
            })
            .map(|module| module.base_address)
    }

    /// Short names of the modules visible from `dtb` whose name starts with
    /// `prefix` (case-insensitive), sorted and deduplicated.
    pub fn module_short_names_with_prefix(&self, dtb: Dtb, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .modules
            .iter()
            .filter(|module| self.module_in_scope(module, dtb))
            .map(|module| module.short_name.clone())
            .filter(|short| {
                short
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            })
            .collect();
        names.sort_unstable_by_key(|name| name.to_ascii_lowercase());
        names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        names
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
            if !self.module_in_scope(&module, dtb) {
                continue;
            }
            if let Some(filter) = module_filter
                && !module.short_name.eq_ignore_ascii_case(filter)
            {
                continue;
            }
            for record in self.symbol_records(module.guid, name) {
                candidates.push(SymbolCandidate {
                    module: module.short_name.clone(),
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
            if !self.module_in_scope(&module, dtb) {
                continue;
            }
            if !module.short_name.eq_ignore_ascii_case(module_short) {
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
            if !self.module_in_scope(&module, dtb) {
                continue;
            }

            if module.contains_address(address)
                && let Some((sym_name, offset)) =
                    self.closest_symbol(module.guid, module.base_address, address)
            {
                return Some((module.short_name.clone(), sym_name, offset));
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
            .find(|module| self.module_in_scope(module, dtb) && module.contains_address(address))
            .map(|module| module.clone())
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
        let entries = self.symbol_addresses.get(&guid)?;
        let last = entries
            .partition_point(|entry| entry.rva <= target_rva)
            .checked_sub(1)?;
        let rva = entries[last].rva;
        let offset = target_rva - rva;
        if offset > 8192 {
            return None;
        }
        let first = entries.partition_point(|entry| entry.rva < rva);
        Some((entries[first].name.clone(), offset))
    }
}
