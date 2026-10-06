//! Acquiring files named by a [`DownloadJob`]: local stores, symbol servers,
//! PDB identity validation, and parallel download with progress.

use super::cache::{store_path, symbols_directory};
use super::{
    DownloadJob, FORCE_DOWNLOADS, PdbIdentity, PdbRequest, SymbolSource, SymbolStore, server_urls,
};
use crate::error::{Error, Result};
use crate::output;
use dashmap::DashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    collections::HashSet,
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

impl DownloadJob {
    pub fn needs_download(&self) -> bool {
        self.pdb.is_some() || !self.path.exists() || *FORCE_DOWNLOADS.get_or_init(|| false)
    }

    pub(super) fn matches_loaded_identity(&self, ages: &DashMap<u128, u32>) -> bool {
        self.pdb.as_ref().is_some_and(|request| {
            ages.get(&request.identity.guid)
                .is_some_and(|age| *age >= request.identity.age)
        })
    }

    /// Whether the managed cache already holds this job's PDB with the right
    /// identity, so acquiring it needs no source at all (only indexing).
    pub fn cached_pdb_matches(&self) -> bool {
        if *FORCE_DOWNLOADS.get_or_init(|| false) {
            return false;
        }
        self.pdb.as_ref().is_some_and(|request| {
            self.path.is_file() && validate_pdb_identity(&self.path, request.identity).is_ok()
        })
    }

    pub(super) fn expected_identity(&self) -> Option<PdbIdentity> {
        self.pdb.as_ref().map(|request| request.identity)
    }

    /// The identity the PDB must have, for a PDB job.
    pub fn pdb_identity(&self) -> Option<PdbIdentity> {
        self.expected_identity()
    }

    /// The path the image records for its PDB, when it has directories.
    pub fn recorded_pdb_path(&self) -> Option<&str> {
        self.pdb.as_ref()?.recorded_path.as_deref()
    }

    /// Acquire the PDB from the cache or a local symbol directory only,
    /// installing it in the cache: whether one had it.
    pub fn acquire_locally(&self) -> Result<bool> {
        let Some(request) = &self.pdb else {
            return Ok(false);
        };
        resolve_local_sources(self, request, &mut Vec::new(), &mut HashSet::new())
    }

    /// Install `bytes` as this job's PDB in the cache, when they are a PDB
    /// with the identity the image records.
    pub fn install_pdb_bytes(&self, bytes: &[u8]) -> Result<()> {
        let expected = self
            .expected_identity()
            .ok_or_else(|| Error::DebugInfo("not a PDB job".into()))?;
        expected
            .matches(pdb_bytes_identity(bytes)?)
            .map_err(Error::DebugInfo)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = unique_temp_path(&self.path);
        if let Err(error) = std::fs::write(&tmp_path, bytes) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(error.into());
        }
        std::fs::rename(tmp_path, &self.path)?;
        Ok(())
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

pub(super) fn task_progress_style() -> ProgressStyle {
    ProgressStyle::with_template(TASK_PROGRESS_TEMPLATE)
        .unwrap()
        .progress_chars("#-")
}

pub(super) fn download_job(job: &DownloadJob, pb: ProgressBar) -> Result<()> {
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

/// The identity of the PDB `bytes` hold.
pub fn pdb_bytes_identity(bytes: &[u8]) -> Result<PdbIdentity> {
    let mut pdb = pdb2::PDB::open(std::io::Cursor::new(bytes))?;
    let info = pdb.pdb_information()?;
    Ok(PdbIdentity {
        guid: info.guid.as_u128(),
        age: info.age,
    })
}

pub(super) fn local_source_candidates(
    root: &Path,
    server_name: &str,
    identity: PdbIdentity,
) -> Vec<PathBuf> {
    vec![
        root.join(server_name),
        store_path(root, server_name, &identity.symbol_store_key()),
    ]
}

/// Copy `source` to `destination` in the cache, through a temporary file
/// renamed into place, so a reader never sees a partial file.
pub fn install_local_file(source: &Path, destination: &Path) -> Result<()> {
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

/// Try the cache and the local symbol directories in `request`'s sources,
/// in order, noting each miss in `attempts`: whether one had the PDB (it is
/// then in the cache).
fn resolve_local_sources(
    job: &DownloadJob,
    request: &PdbRequest,
    attempts: &mut Vec<String>,
    seen_paths: &mut HashSet<PathBuf>,
) -> Result<bool> {
    let force = *FORCE_DOWNLOADS.get_or_init(|| false);
    for source in &request.sources {
        match source {
            SymbolSource::Cache => {
                if force {
                    attempts.push(format!("{}: skipped by force-download", source));
                    continue;
                }
                seen_paths.insert(job.path.clone());
                if !job.path.is_file() {
                    attempts.push(format!("{}: not found", job.path.display()));
                    continue;
                }
                match validate_pdb_identity(&job.path, request.identity) {
                    Ok(()) => return Ok(true),
                    Err(reason) => attempts.push(format!("{}: {}", job.path.display(), reason)),
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
                            install_local_file(&candidate, &job.path)?;
                            return Ok(true);
                        }
                        Err(reason) => {
                            attempts.push(format!("{}: {}", candidate.display(), reason))
                        }
                    }
                }
            }
            SymbolSource::Http(_) => {}
        }
    }
    Ok(false)
}

fn resolve_pdb_job(job: &DownloadJob, request: &PdbRequest, pb: ProgressBar) -> Result<()> {
    let mut attempts = Vec::new();
    let mut seen_paths = HashSet::new();
    if resolve_local_sources(job, request, &mut attempts, &mut seen_paths)? {
        return Ok(());
    }

    for source in &request.sources {
        match source {
            SymbolSource::Cache | SymbolSource::LocalDirectory(_) => {}
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

/// `quiet` hides the progress bars: a background fetch must not draw over
/// the prompt of the thread that spawned it.
pub fn download_jobs_parallel(jobs: Vec<DownloadJob>, quiet: bool) -> Vec<Result<PathBuf>> {
    let mp = Arc::new(if quiet {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    } else {
        MultiProgress::new()
    });

    jobs.into_par_iter()
        .map(|job| {
            let mp = Arc::clone(&mp);
            let bar = (!quiet)
                .then(|| output::native_progress_bar(0, "downloading symbols"))
                .flatten()
                .unwrap_or_else(|| mp.add(ProgressBar::new(0)));
            download_job(&job, bar).map(|_| job.path)
        })
        .collect::<Vec<_>>()
}

impl SymbolStore {
    pub(super) fn build_download_job(
        &self,
        pdb_file_name: &str,
        guid: u128,
        age: u32,
    ) -> Result<(DownloadJob, u128)> {
        let server_name = Self::symbol_server_file_name(pdb_file_name);
        let identity = PdbIdentity { guid, age };
        let key = identity.symbol_store_key();
        let urls = server_urls(&format!("{server_name}/{key}/{server_name}"));
        let storage_dir = symbols_directory().ok_or(Error::StorageNotFound)?;
        let path = store_path(&storage_dir, server_name, &key);

        let job = DownloadJob {
            urls,
            path,
            filename: server_name.to_string(),
            pdb: Some(PdbRequest {
                identity,
                server_name: server_name.to_string(),
                sources: self.symbol_sources(),
                recorded_path: (pdb_file_name.contains(['\\', '/']))
                    .then(|| pdb_file_name.to_string()),
            }),
        };

        Ok((job, guid))
    }
}
