//! Source-line lookup: address to file and line, file and line to addresses,
//! and remapping recorded paths onto local source roots.

use super::{SourceLineEntry, SourceLineExtent, SourceLocation, SourcePathMapping, SymbolStore};
use crate::types::{Dtb, VirtAddr};
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

pub(super) fn remap_source_file(
    recorded: &str,
    mappings: &[SourcePathMapping],
) -> (Option<PathBuf>, bool) {
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
        let (local_path, local_exists) =
            remap_source_file(&location.file, &self.source_paths.read());
        location.local_path = local_path;
        location.local_exists = local_exists;
        Some(SourceLineExtent {
            location,
            end: end_rva.map(|rva| module.base_address + u64::from(rva)),
        })
    }

    /// Resolve a PDB source file and line to every loaded address in the
    /// selected address space. A bare filename matches any recorded basename;
    /// a path matches the full recorded path case-insensitively.
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
            addresses.extend(
                lines
                    .iter()
                    .filter(|entry| {
                        if entry.location.line != line {
                            return false;
                        }
                        if query.matches(&entry.location.file) {
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
}
