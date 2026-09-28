//! Source-line lookup: address to file and line, file and line to addresses,
//! and remapping recorded paths onto local source roots.

use super::{
    LocalSource, LocalSourceDigest, LocalSourceState, SourceChecksum, SourceLineEntry,
    SourceLineExtent, SourceLocation, SourcePathMapping, SymbolStore,
};
use crate::types::{Dtb, VirtAddr};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(super) fn lookup_source_line(
    lines: &[SourceLineEntry],
    rva: u32,
) -> Option<(&SourceLineEntry, Option<u32>)> {
    let index = lines
        .partition_point(|line| line.rva <= rva)
        .checked_sub(1)?;
    let line = &lines[index];
    let next_rva = lines.get(index + 1).map(|next| next.rva);
    let covered = match line.length {
        Some(length) => rva < line.rva.saturating_add(length),
        None => next_rva.is_some_and(|next| rva < next) || rva == line.rva,
    };
    if !covered {
        return None;
    }
    let end_rva = line
        .length
        .map(|length| line.rva.saturating_add(length))
        .or(next_rva);
    Some((line, end_rva))
}

/// The file of a source-line lookup, normalized once so every recorded path
/// is compared in place. Matching ignores ASCII case and treats `\` and `/`
/// alike.
pub(super) enum SourceFileQuery {
    /// A path, which must equal the whole recorded path.
    Path(String),
    /// A bare file name, which must equal the recorded path's last component.
    Name(String),
}

impl SourceFileQuery {
    pub(super) fn new(query: &str) -> Self {
        let query = query.replace('\\', "/");
        if query.contains('/') {
            Self::Path(query)
        } else {
            Self::Name(query)
        }
    }

    pub(super) fn matches(&self, recorded: &str) -> bool {
        match self {
            Self::Path(path) => {
                let fold = |byte: u8| match byte {
                    b'\\' => b'/',
                    byte => byte.to_ascii_lowercase(),
                };
                recorded.len() == path.len()
                    && recorded
                        .bytes()
                        .zip(path.bytes())
                        .all(|(recorded, query)| fold(recorded) == fold(query))
            }
            Self::Name(name) => recorded
                .rsplit(['/', '\\'])
                .next()
                .is_some_and(|base| base.eq_ignore_ascii_case(name)),
        }
    }
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

/// The file a recorded source path maps to under `mappings`, tried in
/// order. A `prefix=root` mapping replaces the recorded prefix with `root`.
/// A bare `root` holds the recorded path's trailing components: the longest
/// that names a file under it wins (`C:\src\drv\queue.c` finds
/// `root/drv/queue.c` before `root/queue.c`), matched exactly first, then
/// ignoring ASCII case. `verify` says whether a file is the one compiled
/// (`None` when that cannot be told); a file that is not is passed over
/// and reported as [`LocalSourceState::Differs`] if nothing better is found.
pub(super) fn remap_source_file(
    recorded: &str,
    mappings: &[SourcePathMapping],
    verify: &mut dyn FnMut(&Path) -> Option<bool>,
) -> Option<LocalSource> {
    let normalized = recorded.replace('\\', "/");
    let lowered = normalized.to_ascii_lowercase();
    let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
    let mut missing = None;
    let mut differs = None;
    for mapping in mappings {
        let relatives: Vec<PathBuf> = match &mapping.recorded_prefix {
            Some(prefix) => {
                let prefix = prefix.replace('\\', "/");
                let prefix_lower = prefix.to_ascii_lowercase();
                if !lowered.starts_with(&prefix_lower)
                    || (normalized.len() != prefix.len()
                        && normalized.as_bytes().get(prefix.len()) != Some(&b'/'))
                {
                    continue;
                }
                safe_source_relative_path(normalized[prefix.len()..].trim_start_matches('/'))
                    .into_iter()
                    .collect()
            }
            None => (0..components.len())
                .filter_map(|start| safe_source_relative_path(&components[start..].join("/")))
                .collect(),
        };
        let root = &mapping.local_root;
        // A bare root that holds no suffix reports the file name under it.
        if let Some(relative) = relatives.last() {
            missing.get_or_insert_with(|| root.join(relative));
        }
        let exact = relatives.iter().map(|relative| Some(root.join(relative)));
        let folded = relatives
            .iter()
            .map(|relative| find_ignoring_case(root, relative));
        for candidate in exact.chain(folded).flatten() {
            if !source_candidate_is_contained_file(root, &candidate) {
                continue;
            }
            if verify(&candidate) == Some(false) {
                differs.get_or_insert(candidate);
                continue;
            }
            return Some(LocalSource {
                path: candidate,
                state: LocalSourceState::Found,
            });
        }
    }
    differs
        .map(|path| LocalSource {
            path,
            state: LocalSourceState::Differs,
        })
        .or(missing.map(|path| LocalSource {
            path,
            state: LocalSourceState::Missing,
        }))
}

/// `root/relative` found component by component ignoring ASCII case, when
/// each component matches exactly one directory entry.
fn find_ignoring_case(root: &Path, relative: &Path) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        let name = component.as_os_str().to_str()?;
        let exact = path.join(name);
        if exact.exists() {
            path = exact;
            continue;
        }
        let mut matches = std::fs::read_dir(&path).ok()?.filter_map(|entry| {
            let entry = entry.ok()?;
            entry
                .file_name()
                .to_str()
                .is_some_and(|entry_name| entry_name.eq_ignore_ascii_case(name))
                .then(|| entry.path())
        });
        let found = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        path = found;
    }
    Some(path)
}

/// The digest of `bytes` of the same kind as `like`.
pub fn source_digest(like: &SourceChecksum, bytes: &[u8]) -> SourceChecksum {
    use sha2::Digest;
    match like {
        SourceChecksum::Md5(_) => SourceChecksum::Md5(md5::Md5::digest(bytes).into()),
        SourceChecksum::Sha1(_) => SourceChecksum::Sha1(sha1::Sha1::digest(bytes).into()),
        SourceChecksum::Sha256(_) => SourceChecksum::Sha256(sha2::Sha256::digest(bytes).into()),
    }
}

/// The checksum a PDB records for a source file, `None` for none or an
/// unexpected length.
pub fn recorded_checksum(checksum: &pdb2::FileChecksum<'_>) -> Option<SourceChecksum> {
    Some(match checksum {
        pdb2::FileChecksum::None => return None,
        pdb2::FileChecksum::Md5(bytes) => SourceChecksum::Md5((*bytes).try_into().ok()?),
        pdb2::FileChecksum::Sha1(bytes) => SourceChecksum::Sha1((*bytes).try_into().ok()?),
        pdb2::FileChecksum::Sha256(bytes) => SourceChecksum::Sha256((*bytes).try_into().ok()?),
    })
}

/// Largest local source file hashed to check it against the PDB.
const MAX_HASHED_SOURCE: u64 = 64 << 20;

impl SymbolStore {
    /// Resolve a virtual address to cached C13 source information.
    pub fn source_location(&self, dtb: Dtb, address: VirtAddr) -> Option<SourceLocation> {
        self.source_line_extent(dtb, address)
            .map(|extent| extent.location)
    }

    /// Resolve a virtual address to its cached C13 source line and exclusive
    /// address extent, which the debugger uses to step a whole source line at
    /// once.
    pub fn source_line_extent(&self, dtb: Dtb, address: VirtAddr) -> Option<SourceLineExtent> {
        let module = self.find_module_for_address(dtb, address)?;
        let rva = u32::try_from(address.0.checked_sub(module.base_address.0)?).ok()?;
        let lines = self.source_lines.get(&module.guid)?;
        let (line, end_rva) = lookup_source_line(&lines, rva)?;
        let mut location = line.location.clone();
        location.local = self.local_source(module.guid, &location.file, &self.source_paths.read());
        Some(SourceLineExtent {
            location,
            end: end_rva.map(|rva| module.base_address + u64::from(rva)),
        })
    }

    /// The local file recorded source `file` of PDB `guid` maps to, checked
    /// against the checksum the PDB records for it.
    fn local_source(
        &self,
        guid: u128,
        file: &str,
        mappings: &[SourcePathMapping],
    ) -> Option<LocalSource> {
        if mappings.is_empty() {
            return None;
        }
        let expected = self
            .source_checksums
            .get(&guid)
            .and_then(|checksums| checksums.get(file).cloned());
        remap_source_file(file, mappings, &mut |path| {
            expected
                .as_ref()
                .and_then(|expected| self.local_digest(path, expected))
                .map(|digest| Some(&digest) == expected.as_ref())
        })
    }

    /// `path`'s digest of the kind of `like`, cached while its modification
    /// time and length hold. `None` when it cannot be read, or is larger
    /// than any source file.
    fn local_digest(&self, path: &Path, like: &SourceChecksum) -> Option<SourceChecksum> {
        let metadata = std::fs::metadata(path).ok()?;
        let (modified, len) = (metadata.modified().ok()?, metadata.len());
        let same_kind = |digest: &SourceChecksum| {
            std::mem::discriminant(digest) == std::mem::discriminant(like)
        };
        if let Some(cached) = self.local_source_digests.lock().get(path)
            && cached.modified == modified
            && cached.len == len
            && same_kind(&cached.digest)
        {
            return Some(cached.digest.clone());
        }
        if len > MAX_HASHED_SOURCE {
            return None;
        }
        let digest = source_digest(like, &std::fs::read(path).ok()?);
        self.local_source_digests.lock().insert(
            path.to_path_buf(),
            LocalSourceDigest {
                modified,
                len,
                digest: digest.clone(),
            },
        );
        Some(digest)
    }

    /// Resolve a PDB source file and line to every loaded address in the
    /// selected address space. A bare filename matches any recorded basename;
    /// a path matches the full recorded path, or the local file it maps to,
    /// case-insensitively.
    pub fn source_addresses(&self, dtb: Dtb, file: &str, line: u32) -> Vec<VirtAddr> {
        let mut addresses = Vec::new();
        let mappings = self.source_paths.read();
        let query = SourceFileQuery::new(file);
        for module in self.modules.iter() {
            if !self.module_in_scope(&module, dtb) {
                continue;
            }
            let Some(lines) = self.source_lines.get(&module.guid) else {
                continue;
            };
            // Each recorded file is mapped once, not once per line.
            let mut mapped: HashMap<&str, bool> = HashMap::new();
            for entry in lines.iter().filter(|entry| entry.location.line == line) {
                let recorded = entry.location.file.as_str();
                let matches = query.matches(recorded)
                    || *mapped.entry(recorded).or_insert_with(|| {
                        self.local_source(module.guid, recorded, &mappings)
                            .is_some_and(|local| {
                                local.path.to_string_lossy().eq_ignore_ascii_case(file)
                            })
                    });
                if matches {
                    addresses.push(module.base_address + u64::from(entry.rva));
                }
            }
        }
        addresses.sort_by_key(|address| address.0);
        addresses.dedup();
        addresses
    }
}
