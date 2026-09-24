//! Acquiring files named by a [`DownloadJob`]: local stores, symbol servers,
//! PDB identity validation, and parallel download with progress.

use super::cache::{store_path, symbols_directory};
use super::{
    DownloadJob, FORCE_DOWNLOADS, PdbIdentity, PdbRequest, SymbolSource, SymbolStore, server_urls,
};
use crate::error::{Error, Result};
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
                seen_paths.insert(job.path.clone());
                if !job.path.is_file() {
                    attempts.push(format!("{}: not found", job.path.display()));
                    continue;
                }
                match validate_pdb_identity(&job.path, request.identity) {
                    Ok(()) => return Ok(()),
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
            download_job(&job, mp.add(ProgressBar::new(0))).map(|_| job.path)
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
            }),
        };

        Ok((job, guid))
    }
}
