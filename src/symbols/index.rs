//! The fuzzy completion index over symbol and type names: sorted names with
//! precomputed bare-name offsets and prefix keys, searched in parallel chunks.

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rayon::slice::ParallelSlice;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::mem::swap;

use super::glob_matches;

#[derive(Default, Clone)]
pub struct SymbolIndex {
    /// Symbol/type names, sorted and deduped. Matched fuzzily by `search`
    pub names: Vec<String>,
    /// Byte offsets of each name's bare symbol, avoiding a reverse scan during
    /// every completion search.
    bare_offsets: Vec<u32>,
    /// First four bare-name bytes, ASCII-lowercased, packed most significant byte
    /// first, and zero-padded. Prefix searches scan these keys before reading names.
    prefix_keys: Vec<u32>,
}

impl SymbolIndex {
    pub fn from_names(names: Vec<String>) -> Self {
        let (bare_offsets, prefix_keys): (Vec<u32>, Vec<u32>) = names
            .par_iter()
            .map(|name| {
                let bare_offset = name
                    .rfind('!')
                    .map_or(0, |separator| separator.saturating_add(1))
                    as u32;
                (bare_offset, prefix_key(bare_name(name, bare_offset)))
            })
            .unzip();
        Self {
            names,
            bare_offsets,
            prefix_keys,
        }
    }

    /// Search names best-first with smart-case ranking (case-insensitive unless
    /// the query has uppercase). A plain ASCII query is first reduced to a
    /// bounded candidate set by one cheap pass that keeps the names whose bare
    /// symbol contains the query, and only those are scored. This deliberately
    /// drops gap-only fuzzy matches such as `PsGtPrcId`, which would otherwise
    /// cost a full dynamic-programming scan of every name on each keystroke.
    /// Empty query returns the first `limit` names. On a module-qualified index
    /// a query without `!` matches the bare name, so `Ke*` finds
    /// `nt!KeBugCheckEx` without the `nt!` counting as text.
    pub fn search(&self, query: &str, limit: usize) -> Vec<String> {
        if query.is_empty() || limit == 0 {
            return self.names.iter().take(limit).cloned().collect();
        }
        let qualified_query = query.contains('!');
        if query
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'*' | b'?'))
        {
            return self
                .names
                .iter()
                .zip(&self.bare_offsets)
                .filter(|(name, bare_offset)| {
                    glob_matches(query, haystack(qualified_query, name, **bare_offset), true)
                })
                .take(limit)
                .map(|(name, _)| name.clone())
                .collect();
        }

        let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
        let (range_start, range_end) = qualified_search_range(&self.names, query);
        let names = &self.names[range_start..range_end];
        let top = if plain_ascii_query(query) {
            let fragment = query
                .rsplit_once('!')
                .map_or(query, |(_, fragment)| fragment);
            let candidates = self.candidates(fragment, range_start, range_end);
            let chunk_size = candidates
                .len()
                .div_ceil(rayon::current_num_threads())
                .max(1);
            candidates
                .par_chunks(chunk_size)
                .map(|chunk| {
                    score_index_chunk(
                        chunk,
                        &self.names,
                        &self.bare_offsets,
                        qualified_query,
                        &pattern,
                        limit,
                    )
                })
                .reduce(
                    || BinaryHeap::with_capacity(limit),
                    |left, right| merge_top(left, right, limit),
                )
        } else {
            let chunk_size = names.len().div_ceil(rayon::current_num_threads()).max(1);
            names
                .par_chunks(chunk_size)
                .enumerate()
                .map(|(chunk_number, chunk)| {
                    score_name_chunk(
                        chunk,
                        &self.bare_offsets,
                        qualified_query,
                        &pattern,
                        limit,
                        range_start + chunk_number * chunk_size,
                    )
                })
                .reduce(
                    || BinaryHeap::with_capacity(limit),
                    |left, right| merge_top(left, right, limit),
                )
        };

        let mut scored: Vec<(u32, &String)> = top
            .into_iter()
            .map(|(Reverse(score), name)| (score, name))
            .collect();

        // The bounded heaps contain only the top `limit`; ties break alphabetically.
        let by_rank =
            |a: &(u32, &String), b: &(u32, &String)| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1));
        scored.sort_unstable_by(by_rank);
        scored.into_iter().map(|(_, name)| name.clone()).collect()
    }

    /// The names worth fuzzy-scoring for `needle`, as indices into `names`,
    /// restricted to `range_start..range_end` and capped at [`CANDIDATE_CAP`].
    ///
    /// Bare-name prefix matches come first and, when any exist, come alone:
    /// that is what typing a prefix means, and they are found by scanning the
    /// packed key column rather than the names. Only when no name starts with
    /// `needle` is the far more expensive contiguous-substring scan of the
    /// names themselves worth running.
    fn candidates(&self, needle: &str, range_start: usize, range_end: usize) -> Vec<u32> {
        if range_start >= range_end {
            return Vec::new();
        }
        // `module!` with nothing typed after it: every name in range is a
        // candidate, and the scorer ranks the module's own names first.
        if needle.is_empty() {
            let end = range_end.min(range_start.saturating_add(CANDIDATE_CAP));
            return (range_start..end).map(|index| index as u32).collect();
        }
        let prefixed = self.prefix_candidates(needle, range_start, range_end);
        if !prefixed.is_empty() {
            return prefixed;
        }
        self.substring_candidates(needle, range_start, range_end)
    }

    /// Indices whose bare name starts with `needle`, case-insensitively.
    ///
    /// The packed key holds four bytes, so a longer `needle` still filters on
    /// its first four and only the survivors are compared against the name
    /// itself.
    fn prefix_candidates(&self, needle: &str, range_start: usize, range_end: usize) -> Vec<u32> {
        let compared = needle.len().min(4) as u32;
        let shift = 32 - 8 * compared;
        let needle_key = prefix_key(needle) >> shift;
        let (chunk_size, per_chunk_cap) = candidate_chunking(range_end - range_start);
        let chunks: Vec<Vec<u32>> = self.prefix_keys[range_start..range_end]
            .par_chunks(chunk_size)
            .enumerate()
            .map(|(chunk_number, chunk)| {
                let base = range_start + chunk_number * chunk_size;
                let mut candidates = Vec::new();
                for (offset, key) in chunk.iter().enumerate() {
                    if candidates.len() >= per_chunk_cap {
                        break;
                    }
                    if key >> shift != needle_key {
                        continue;
                    }
                    let index = base + offset;
                    if needle.len() > 4
                        && !ascii_prefix_case_insensitive(
                            bare_name(&self.names[index], self.bare_offsets[index]),
                            needle,
                        )
                    {
                        continue;
                    }
                    candidates.push(index as u32);
                }
                candidates
            })
            .collect();
        collect_candidates(chunks)
    }

    /// Indices whose bare name contains `needle` anywhere, case-insensitively.
    /// This reads every name in the range, so it is the fallback tier.
    fn substring_candidates(&self, needle: &str, range_start: usize, range_end: usize) -> Vec<u32> {
        let (chunk_size, per_chunk_cap) = candidate_chunking(range_end - range_start);
        let chunks: Vec<Vec<u32>> = self.names[range_start..range_end]
            .par_chunks(chunk_size)
            .enumerate()
            .map(|(chunk_number, chunk)| {
                let base = range_start + chunk_number * chunk_size;
                let mut candidates = Vec::new();
                for (offset, name) in chunk.iter().enumerate() {
                    if candidates.len() >= per_chunk_cap {
                        break;
                    }
                    let index = base + offset;
                    if ascii_contains_case_insensitive(
                        bare_name(name, self.bare_offsets[index]),
                        needle,
                    ) {
                        candidates.push(index as u32);
                    }
                }
                candidates
            })
            .collect();
        collect_candidates(chunks)
    }
}

fn push_top<'a>(
    top: &mut BinaryHeap<(Reverse<u32>, &'a String)>,
    score: u32,
    name: &'a String,
    limit: usize,
) {
    let candidate = (Reverse(score), name);
    if top.len() < limit || top.peek().is_some_and(|worst| candidate < *worst) {
        top.push(candidate);
        if top.len() > limit {
            top.pop();
        }
    }
}

fn merge_top<'a>(
    mut left: BinaryHeap<(Reverse<u32>, &'a String)>,
    mut right: BinaryHeap<(Reverse<u32>, &'a String)>,
    limit: usize,
) -> BinaryHeap<(Reverse<u32>, &'a String)> {
    if left.len() < right.len() {
        swap(&mut left, &mut right);
    }
    for candidate in right {
        left.push(candidate);
        if left.len() > limit {
            left.pop();
        }
    }
    left
}

/// Restrict a case-sensitive qualified query to one module's contiguous name
/// range. Smart-case lowercase queries cannot use this range because matching
/// module names with different casing would no longer be possible on the
/// case-sensitive index ordering.
fn qualified_search_range(names: &[String], query: &str) -> (usize, usize) {
    let Some((module, _)) = query.split_once('!') else {
        return (0, names.len());
    };
    if module.is_empty()
        || query.chars().any(char::is_whitespace)
        || !query.chars().any(char::is_uppercase)
        || module
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(*byte, b'!' | b'^' | b'\'' | b'\\'))
    {
        return (0, names.len());
    }

    // `!` is the last byte of the lower bound. Replacing it with the next
    // ASCII byte gives an exclusive upper bound for every string beginning
    // with `<module>!`, without scanning that module to find its end.
    let lower = format!("{module}!");
    let upper = format!("{module}\"");
    let start = names.partition_point(|name| name < &lower);
    let end = names.partition_point(|name| name < &upper);
    (start, end)
}

/// Maximum candidates scored per query, bounding work on large symbol indexes.
const CANDIDATE_CAP: usize = 50_000;

fn bare_name(name: &str, bare_offset: u32) -> &str {
    &name[bare_offset as usize..]
}

fn haystack(qualified_query: bool, name: &str, bare_offset: u32) -> &str {
    if qualified_query {
        name
    } else {
        bare_name(name, bare_offset)
    }
}

fn score_index_chunk<'a>(
    indices: &[u32],
    names: &'a [String],
    bare_offsets: &[u32],
    qualified_query: bool,
    pattern: &Pattern,
    limit: usize,
) -> BinaryHeap<(Reverse<u32>, &'a String)> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();
    let mut top = BinaryHeap::with_capacity(limit);
    for &index in indices {
        let index = index as usize;
        let name = &names[index];
        let text = haystack(qualified_query, name, bare_offsets[index]);
        if let Some(score) = pattern.score(Utf32Str::new(text, &mut buf), &mut matcher) {
            push_top(&mut top, score, name, limit);
        }
    }
    top
}

fn score_name_chunk<'a>(
    names: &'a [String],
    bare_offsets: &[u32],
    qualified_query: bool,
    pattern: &Pattern,
    limit: usize,
    base: usize,
) -> BinaryHeap<(Reverse<u32>, &'a String)> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();
    let mut top = BinaryHeap::with_capacity(limit);
    for (offset, name) in names.iter().enumerate() {
        let index = base + offset;
        let text = haystack(qualified_query, name, bare_offsets[index]);
        if let Some(score) = pattern.score(Utf32Str::new(text, &mut buf), &mut matcher) {
            push_top(&mut top, score, name, limit);
        }
    }
    top
}

fn plain_ascii_query(query: &str) -> bool {
    if !query.is_ascii() || query.is_empty() || query.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return false;
    }
    let bytes = query.as_bytes();
    !bytes.iter().any(|byte| matches!(*byte, b'*' | b'?'))
        && !bytes
            .first()
            .is_some_and(|byte| matches!(*byte, b'!' | b'^' | b'\'' | b'\\'))
        && bytes.last() != Some(&b'$')
        && !bytes.ends_with(b"\\$")
}

/// Whether `needle` is a case-insensitive ASCII prefix of `haystack`. Byte
/// comparison, so a non-ASCII name simply fails to match an ASCII needle.
fn ascii_prefix_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.len() >= needle.len()
        && haystack.as_bytes()[..needle.len()].eq_ignore_ascii_case(needle.as_bytes())
}

/// Whether `haystack` contains `needle` case-insensitively. A non-ASCII name
/// cannot be folded this way and is kept, leaving the decision to the scorer.
/// This reads every name in the range it is called over, so it is bounded by
/// memory bandwidth rather than by the comparison.
fn ascii_contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || !haystack.is_ascii() {
        return true;
    }
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// The first four bytes of `bare`, ASCII-lowercased and packed most
/// significant byte first, so comparing the top `n` bytes of two keys
/// compares their first `n` characters. Shorter names pad with zero, which no
/// query byte can equal.
fn prefix_key(bare: &str) -> u32 {
    let bytes = bare.as_bytes();
    let mut key = 0u32;
    for index in 0..4 {
        let byte = bytes.get(index).copied().unwrap_or(0);
        key = (key << 8) | u32::from(byte.to_ascii_lowercase());
    }
    key
}

/// Concatenate capped per-chunk candidate lists into one capped list.
fn collect_candidates(chunks: Vec<Vec<u32>>) -> Vec<u32> {
    let mut candidates = Vec::with_capacity(chunks.iter().map(Vec::len).sum());
    for chunk in chunks {
        let remaining = CANDIDATE_CAP.saturating_sub(candidates.len());
        if remaining == 0 {
            break;
        }
        candidates.extend(chunk.into_iter().take(remaining));
    }
    candidates
}

/// One chunk per thread over `len` entries, and the share of the candidate cap
/// each chunk may fill.
fn candidate_chunking(len: usize) -> (usize, usize) {
    let chunk_size = len.div_ceil(rayon::current_num_threads()).max(1);
    let chunk_count = len.div_ceil(chunk_size).max(1);
    (chunk_size, CANDIDATE_CAP.div_ceil(chunk_count).max(1))
}
