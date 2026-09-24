//! Loading module symbols: discovery plans, acquisition and indexing
//! workers, per-module status, and the load report.

use super::{
    Guest, ModuleInfo, ModuleSymbolDiagnostic, ModuleSymbolLoadReport, ProcessInfo, SessionSpace,
};
use crate::{
    error::Result,
    phys::PhysMem,
    symbols::{
        DownloadJob, ModuleSymbolDiscovery, ModuleSymbolLoad, ModuleSymbolSource,
        ModuleSymbolStatus, SymbolIndexDiagnostic, SymbolStore, download::download_jobs_parallel,
    },
    types::*,
};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

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
            ModuleSymbolStatus::Fetching => {
                self.fetching += 1;
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
        self.fetching += other.fetching;
        self.diagnostic_count += other.diagnostic_count;
        self.diagnostics.extend(other.diagnostics);
    }
}

/// What symbol discovery found for a batch of modules, before any file or
/// network work (see [`Guest::plan_module_symbol_loads`]).
#[derive(Default)]
struct ModuleSymbolPlan {
    /// PDB already on disk; only indexing remains.
    ready: Vec<ModuleSymbolLoad>,
    /// PDB identity known; the file must be acquired.
    downloads: Vec<ModuleSymbolLoad>,
    /// Headers unreadable in memory; the image must be fetched to learn the
    /// PDB identity, then treated as `downloads`.
    image_jobs: Vec<(DownloadJob, ModuleInfo)>,
}

impl ModuleSymbolPlan {
    fn queue(&mut self, symbols: &SymbolStore, load: ModuleSymbolLoad) {
        // Parsed already, or on disk with the right identity: no source to
        // consult, so it is never a fetch (which the stop render defers).
        if symbols.has_matching_pdb(&load.job) || load.job.cached_pdb_matches() {
            self.ready.push(load);
        } else {
            self.downloads.push(load);
        }
    }

    /// Split off everything that needs the network, leaving `ready`.
    fn take_fetches(&mut self) -> Self {
        Self {
            ready: Vec::new(),
            downloads: std::mem::take(&mut self.downloads),
            image_jobs: std::mem::take(&mut self.image_jobs),
        }
    }

    fn absorb(&mut self, other: Self) {
        self.ready.extend(other.ready);
        self.downloads.extend(other.downloads);
        self.image_jobs.extend(other.image_jobs);
    }

    fn needs_fetch(&self) -> bool {
        !self.downloads.is_empty() || !self.image_jobs.is_empty()
    }

    fn len(&self) -> usize {
        self.ready.len() + self.downloads.len() + self.image_jobs.len()
    }

    fn modules(&self) -> impl Iterator<Item = &ModuleInfo> {
        self.ready
            .iter()
            .chain(&self.downloads)
            .map(|load| &load.module)
            .chain(self.image_jobs.iter().map(|(_, module)| module))
    }

    fn module_names(&self) -> Vec<String> {
        self.modules().map(|module| module.name.clone()).collect()
    }
}

impl Guest {
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

    fn is_session_space(addr: VirtAddr) -> bool {
        let prefix = addr.0 >> 44;
        prefix == 0xFFFF8 || prefix == 0xFFFF9 || prefix == 0xFFFFA
    }

    /// Load symbols for `modules` under `dtb`: discover each module's PDB
    /// identity from guest memory, acquire the PDBs (cache, local stores,
    /// symbol servers), index them. Blocks for the whole of it; the stop
    /// render uses [`Guest::load_module_symbols_or_fetch_later`] instead so a
    /// stack walk through an uncached module never waits on the network.
    pub fn load_module_symbols(
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        session_space: SessionSpace,
        arch: Arch,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut report = ModuleSymbolLoadReport::new(modules.len());
        let plan = Self::plan_module_symbol_loads(
            phys,
            symbols,
            modules,
            dtb,
            session_space,
            arch,
            &mut report,
        );
        let stale_identities =
            Self::complete_module_symbol_loads(symbols, plan, dtb, &mut report, false);

        // Modules whose remembered PDB no longer resolves: forget the record
        // and rediscover them from the target.
        if !stale_identities.is_empty() {
            for module in &stale_identities {
                symbols.forget_module_identity(module);
            }
            report.absorb(Self::load_module_symbols(
                phys,
                symbols,
                stale_identities,
                dtb,
                session_space,
                arch,
            )?);
        }

        Ok(report)
    }

    /// The stop-render variant of [`Guest::load_module_symbols`]: index what
    /// is already on disk now, and hand anything that needs a download to a
    /// background thread. Frames in a module being fetched render as
    /// `module+offset` until it lands; the store's load generation moves when
    /// it does, so the session re-resolves deferred breakpoints and the next
    /// backtrace shows names. Start and finish are reported through the
    /// store's notices.
    ///
    /// Discovery (guest memory) runs on the caller's thread: a KD-mediated
    /// memory source is only usable from the thread that owns the transport.
    /// A remembered identity that turns out stale is rediscovered once, here,
    /// before anything is handed off.
    pub fn load_module_symbols_or_fetch_later(
        phys: &PhysMem,
        symbols: &Arc<SymbolStore>,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        arch: Arch,
    ) -> ModuleSymbolLoadReport {
        let mut report = ModuleSymbolLoadReport::new(modules.len());
        let mut plan = Self::plan_module_symbol_loads(
            phys,
            symbols,
            modules,
            dtb,
            SessionSpace::Load,
            arch,
            &mut report,
        );
        let mut deferred = plan.take_fetches();
        let stale = Self::complete_module_symbol_loads(symbols, plan, dtb, &mut report, false);
        if !stale.is_empty() {
            for module in &stale {
                symbols.forget_module_identity(module);
            }
            let mut replan = Self::plan_module_symbol_loads(
                phys,
                symbols,
                stale,
                dtb,
                SessionSpace::Load,
                arch,
                &mut report,
            );
            deferred.absorb(replan.take_fetches());
            for module in
                Self::complete_module_symbol_loads(symbols, replan, dtb, &mut report, false)
            {
                Self::apply_module_symbol_status(
                    symbols,
                    &mut report,
                    dtb,
                    &module,
                    ModuleSymbolStatus::Failed(
                        "remembered PDB no longer matches the image".to_string(),
                    ),
                );
            }
        }

        if !deferred.needs_fetch() {
            return report;
        }
        let names = deferred.module_names();
        let deferred_bases: Vec<_> = deferred
            .modules()
            .map(|module| module.base_address)
            .collect();
        for module in deferred.modules() {
            Self::apply_module_symbol_status(
                symbols,
                &mut report,
                dtb,
                module,
                ModuleSymbolStatus::Fetching,
            );
        }
        symbols.push_notice(format!(
            "fetching symbols for {} in the background; frames there show module+offset \
             until it finishes (lm shows `fetching`)",
            names.join(", ")
        ));

        let store = Arc::clone(symbols);
        let spawned = std::thread::Builder::new()
            .name("ntoseye-symbol-fetch".to_string())
            .spawn(move || {
                let symbols = store;
                let mut report = ModuleSymbolLoadReport::new(deferred.len());
                let stale =
                    Self::complete_module_symbol_loads(&symbols, deferred, dtb, &mut report, true);
                for module in &stale {
                    symbols.forget_module_identity(module);
                    Self::apply_module_symbol_status(
                        &symbols,
                        &mut report,
                        dtb,
                        module,
                        ModuleSymbolStatus::Failed(
                            "remembered PDB no longer matches the image; run .reload <module>"
                                .to_string(),
                        ),
                    );
                }
                symbols.push_notice(format!(
                    "background symbol fetch finished for {}: {} loaded, {} failed",
                    names.join(", "),
                    report.loaded,
                    report.failed + report.no_pdb
                ));
            });
        if let Err(error) = spawned {
            let error = error.to_string();
            report.fetching -= deferred_bases.len();
            for base_address in deferred_bases {
                let status = ModuleSymbolStatus::Failed(error.clone());
                symbols.set_module_symbol_status(dtb, base_address, status.clone());
                report.record_status(&status);
            }
            symbols.push_notice(format!("could not start background symbol fetch: {error}"));
        }
        report
    }

    /// Discovery half of a symbol load: read each module's debug directory
    /// from guest memory (or its remembered identity) and sort the modules
    /// into loads whose PDB is already on disk, loads that need a download,
    /// and modules whose headers were unreadable so the image itself must be
    /// fetched to learn the PDB identity. Touches guest memory; never the
    /// network.
    fn plan_module_symbol_loads(
        phys: &PhysMem,
        symbols: &SymbolStore,
        modules: Vec<ModuleInfo>,
        dtb: Dtb,
        session_space: SessionSpace,
        arch: Arch,
        report: &mut ModuleSymbolLoadReport,
    ) -> ModuleSymbolPlan {
        let mut plan = ModuleSymbolPlan::default();

        for module in modules {
            if session_space == SessionSpace::Skip && Self::is_session_space(module.base_address) {
                Self::apply_module_symbol_status(
                    symbols,
                    report,
                    dtb,
                    &module,
                    ModuleSymbolStatus::Skipped,
                );
                continue;
            }

            match symbols.extract_download_job(phys, dtb, &module, arch) {
                Ok(ModuleSymbolDiscovery::Ready { job, guid, source }) => {
                    plan.queue(
                        symbols,
                        ModuleSymbolLoad::new(job, guid, source, module, dtb),
                    );
                }
                Ok(ModuleSymbolDiscovery::NeedsImage { image_job }) => {
                    plan.image_jobs.push((image_job, module));
                }
                Err(_e) if module.time_date_stamp.is_some() => {
                    let tds = module.time_date_stamp.unwrap();
                    match SymbolStore::build_image_download_job(&module.name, tds, module.size) {
                        Ok(image_job) => plan.image_jobs.push((image_job, module)),
                        Err(e) => Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        ),
                    }
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }
        plan
    }

    /// Acquisition half of a symbol load: download images and PDBs the plan
    /// asked for, then index everything that is on disk. Files and network
    /// only, so it may run off the session thread. Returns the modules whose
    /// remembered identity no longer resolves; the caller decides whether to
    /// rediscover them (needs guest memory) or give up.
    fn complete_module_symbol_loads(
        symbols: &SymbolStore,
        plan: ModuleSymbolPlan,
        dtb: Dtb,
        report: &mut ModuleSymbolLoadReport,
        quiet: bool,
    ) -> Vec<ModuleInfo> {
        let ModuleSymbolPlan {
            mut ready,
            mut downloads,
            image_jobs,
        } = plan;

        let image_results = download_jobs_parallel(
            image_jobs.iter().map(|(job, _)| job.clone()).collect(),
            quiet,
        );
        for ((image_job, module), result) in image_jobs.into_iter().zip(image_results) {
            match result {
                Ok(_) => match symbols.extract_download_job_from_image_file(&image_job.path) {
                    Ok(Some((job, guid))) => {
                        let load = ModuleSymbolLoad::new(
                            job,
                            guid,
                            ModuleSymbolSource::Image,
                            module,
                            dtb,
                        );
                        if symbols.has_matching_pdb(&load.job) || load.job.cached_pdb_matches() {
                            ready.push(load);
                        } else {
                            downloads.push(load);
                        }
                    }
                    Ok(None) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::MissingDebugInfo,
                        );
                    }
                    Err(e) => {
                        Self::apply_module_symbol_status(
                            symbols,
                            report,
                            dtb,
                            &module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                },
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        let download_results = download_jobs_parallel(
            downloads.iter().map(|load| load.job.clone()).collect(),
            quiet,
        );
        let mut stale_identities: Vec<ModuleInfo> = Vec::new();
        for (load, result) in downloads.into_iter().zip(download_results) {
            match result {
                Ok(_) => ready.push(load),
                Err(_) if matches!(load.source, ModuleSymbolSource::Identity) => {
                    stale_identities.push(load.module);
                }
                Err(e) => {
                    Self::apply_module_symbol_status(
                        symbols,
                        report,
                        dtb,
                        &load.module,
                        ModuleSymbolStatus::Failed(e.to_string()),
                    );
                }
            }
        }

        if !ready.is_empty() {
            let pb = if quiet {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(ready.len() as u64)
            };
            pb.set_style(
                ProgressStyle::with_template("Indexing [{bar:40}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("#-"),
            );

            // Two modules can share a PDB guid, and indexing one guid is
            // serialized behind a per-guid `OnceLock` inside the symbol store.
            // Indexing also nests rayon, and a worker that blocks in a nested
            // region steals other items from this very loop: if it picked up a
            // second module with the guid it is already initializing, it would
            // park on that `OnceLock` waiting for itself. Give the parallel
            // pass one module per guid and run any duplicates afterwards, where
            // they take the already-indexed fast path.
            let (first_per_guid, duplicate_guids) =
                partition_first_occurrence(ready, |load| load.guid);

            let mut results = first_per_guid
                .into_par_iter()
                .map(|load| {
                    let result = symbols.load_downloaded_pdb(&load);
                    pb.inc(1);
                    (load, result)
                })
                .collect::<Vec<_>>();
            results.extend(duplicate_guids.into_iter().map(|load| {
                let result = symbols.load_downloaded_pdb(&load);
                pb.inc(1);
                (load, result)
            }));

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
                            report,
                            dtb,
                            &load.module,
                            ModuleSymbolStatus::Failed(e.to_string()),
                        );
                    }
                }
            }
        }

        stale_identities
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
        Self::load_module_symbols(
            phys,
            symbols,
            modules,
            dtb,
            SessionSpace::Skip,
            self.ntoskrnl.arch(),
        )
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

        let mut report = Self::load_module_symbols(
            phys,
            symbols,
            missing,
            dtb,
            SessionSpace::Skip,
            self.ntoskrnl.arch(),
        )?;
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
        Self::load_module_symbols(
            phys,
            symbols,
            modules,
            dtb,
            SessionSpace::Load,
            self.ntoskrnl.arch(),
        )
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
        Self::load_module_symbols(
            phys,
            symbols,
            modules,
            dtb,
            SessionSpace::Load,
            self.ntoskrnl.arch(),
        )
    }
}

/// Split `items` into the first item per distinct key and every later item
/// sharing a key already seen, preserving input order in both halves.
///
/// Used to keep a parallel pass to one item per key while still processing the
/// rest; nothing is dropped.
fn partition_first_occurrence<T, K: Eq + std::hash::Hash>(
    items: Vec<T>,
    key: impl Fn(&T) -> K,
) -> (Vec<T>, Vec<T>) {
    let mut first = Vec::with_capacity(items.len());
    let mut rest = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(key(&item)) {
            first.push(item);
        } else {
            rest.push(item);
        }
    }
    (first, rest)
}

#[cfg(test)]
mod tests {
    use super::partition_first_occurrence;
    use crate::guest::ModuleSymbolLoadReport;
    use crate::symbols::SymbolIndexDiagnostic;

    /// Indexing one PDB guid is serialized behind a per-guid `OnceLock`, and a
    /// rayon worker blocked in a nested parallel region steals other items
    /// from the same loop. Two modules sharing a guid must therefore never be
    /// in the parallel pass together, and neither may be dropped.
    #[test]
    fn same_key_items_are_deferred_out_of_the_parallel_pass() {
        let modules = vec![
            (7u32, "a.sys"),
            (9, "b.sys"),
            (7, "c.sys"),
            (8, "d.sys"),
            (7, "e.sys"),
            (9, "f.sys"),
        ];

        let (first, rest) = partition_first_occurrence(modules, |(guid, _)| *guid);

        assert_eq!(first, vec![(7, "a.sys"), (9, "b.sys"), (8, "d.sys")]);
        assert_eq!(rest, vec![(7, "c.sys"), (7, "e.sys"), (9, "f.sys")]);
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
