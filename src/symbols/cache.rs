//! The managed on-disk cache: its location and symbol-store layout, module
//! identities persisted across sessions, and complete module images kept in it.

use super::download::download_job;
use super::ntoseye_home;
use super::{DownloadJob, ImageFetch, SymbolStore, server_urls};
use crate::{
    error::{Error, Result},
    guest::ModuleInfo,
    pe::{PeImage, read_pe_image_from_file},
};
use indicatif::ProgressBar;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, PoisonError, mpsc},
};

pub(super) fn symbols_directory() -> Option<PathBuf> {
    let symbols_path = ntoseye_home()?.join("symbols");
    // SymSrv treats a directory as a symbol store only when `pingme.txt`
    // exists at its root; Ghidra also wants `000admin` (symstore's
    // transaction directory) or it guesses the layout and warns.
    std::fs::create_dir_all(symbols_path.join("000admin")).ok()?;
    let pingme = symbols_path.join("pingme.txt");
    if !pingme.exists() {
        File::create(pingme).ok()?;
    }
    Some(symbols_path)
}

/// Where a symbol store keeps `file_name` under `key`: the layout DbgHelp,
/// symstore, and the public symbol servers share, so the cache is a store
/// any of them can read and any of theirs can serve as the cache.
pub(super) fn store_path(root: &Path, file_name: &str, key: &str) -> PathBuf {
    root.join(file_name).join(key).join(file_name)
}

/// The image identity the symbol server keys on: file name, `TimeDateStamp`,
/// `SizeOfImage`. The loader's module record carries all three.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ModuleIdentity {
    pub(super) name: String,
    pub(super) time_date_stamp: u32,
    pub(super) size_of_image: u32,
}

impl ModuleIdentity {
    pub(super) fn of(module: &ModuleInfo) -> Option<Self> {
        Some(Self {
            name: SymbolStore::symbol_server_file_name(&module.name).to_ascii_lowercase(),
            time_date_stamp: module.time_date_stamp?,
            size_of_image: module.size,
        })
    }
}

/// What [`SymbolStore::build_download_job`] needs to name a PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PdbReference {
    pub(super) server_name: String,
    pub(super) guid: u128,
    pub(super) age: u32,
}

/// Module identity to PDB map persisted across sessions, one tab-separated
/// line per module, so a module seen before is identified without reading
/// its headers, debug directory, and CodeView record from the target.
pub(super) struct ModuleIdentities {
    path: Option<PathBuf>,
    entries: std::sync::Mutex<HashMap<ModuleIdentity, PdbReference>>,
}

impl ModuleIdentities {
    pub(super) fn open(path: Option<PathBuf>) -> Self {
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

    pub(super) fn get(&self, identity: &ModuleIdentity) -> Option<PdbReference> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity)
            .cloned()
    }

    /// Record a module's PDB. A failure to persist only costs the next
    /// session the reads this one already paid.
    pub(super) fn insert(&self, identity: ModuleIdentity, reference: PdbReference) {
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
    pub(super) fn remove(&self, identity: &ModuleIdentity) {
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

impl SymbolStore {
    /// Ensure the module's on-disk PE image (matched by TimeDateStamp +
    /// SizeOfImage, the symbol-server image key) is in the image cache,
    /// downloading it if absent, and return its path.
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

    /// The module image's path when it is already in the cache; otherwise
    /// `None`, with the download queued for a background thread (once, however
    /// often this is asked) and its outcome reported through the store's
    /// notices. For callers that must answer at once, such as a protocol
    /// request with a client-side timeout.
    pub fn image_or_fetch_later(
        self: &Arc<Self>,
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<Option<PathBuf>> {
        let job = Self::build_image_download_job(image_file_name, time_date_stamp, size_of_image)?;
        if !job.needs_download() {
            return Ok(Some(job.path));
        }
        if !self.image_fetches.lock().insert(job.path.clone()) {
            return Ok(None);
        }
        let path = job.path.clone();
        let name = job.filename.clone();
        if let Err(error) = self.queue_image_fetch(job) {
            self.image_fetches.lock().remove(&path);
            return Err(Error::DebugInfo(format!(
                "could not start the background fetch of {image_file_name}: {error}"
            )));
        }
        self.push_notice(format!("fetching {name} in the background"));
        Ok(None)
    }

    /// Hand `job` to the background fetch worker, starting it on first use.
    /// The worker holds the store weakly, so it ends once the store is gone.
    fn queue_image_fetch(self: &Arc<Self>, job: DownloadJob) -> io::Result<()> {
        let mut queue = self.image_queue.lock();
        let sender = match &mut *queue {
            Some(sender) => sender,
            None => {
                let (sender, jobs) = mpsc::channel::<DownloadJob>();
                let store = Arc::downgrade(self);
                std::thread::Builder::new()
                    .name("ntoseye-image-fetch".to_string())
                    .spawn(move || {
                        for job in jobs {
                            let outcome = download_job(&job, ProgressBar::hidden());
                            let Some(store) = store.upgrade() else {
                                return;
                            };
                            store.image_fetches.lock().remove(&job.path);
                            let name = &job.filename;
                            store.push_notice(match outcome {
                                Ok(()) => format!("background fetch finished for {name}"),
                                Err(error) => {
                                    format!("background fetch failed for {name}: {error}")
                                }
                            });
                        }
                    })?;
                queue.insert(sender)
            }
        };
        sender
            .send(job)
            .map_err(|_| io::Error::other("the background fetch worker has stopped"))
    }

    /// The module's complete on-disk PE image from the image cache, expanded
    /// once per session, downloaded first when absent if `fetch` allows. Lets
    /// the unwinder read unwind tables without the target, or recover them
    /// when the in-memory `.pdata` is paged out.
    pub fn module_image_on_disk(
        &self,
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
        fetch: ImageFetch,
    ) -> Result<Arc<PeImage>> {
        let job = Self::build_image_download_job(image_file_name, time_date_stamp, size_of_image)?;
        if let Some(image) = self.on_disk_images.get(&job.path) {
            return Ok(Arc::clone(&image));
        }
        if fetch == ImageFetch::Download {
            download_job(&job, ProgressBar::new(0))?;
        }
        let image = Arc::new(read_pe_image_from_file(&job.path)?);
        self.on_disk_images.insert(job.path, Arc::clone(&image));
        Ok(image)
    }

    pub fn build_image_download_job(
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<DownloadJob> {
        let server_name = Self::symbol_server_file_name(image_file_name);
        let key = format!("{time_date_stamp:08X}{size_of_image:X}");
        let urls = server_urls(&format!("{server_name}/{key}/{server_name}"));
        let storage_dir = symbols_directory().ok_or(Error::StorageNotFound)?;
        let path = store_path(&storage_dir, server_name, &key);

        Ok(DownloadJob {
            urls,
            path,
            filename: server_name.to_string(),
            pdb: None,
        })
    }

    pub(super) fn symbol_server_file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    pub(super) fn module_identities(&self) -> &ModuleIdentities {
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
}
