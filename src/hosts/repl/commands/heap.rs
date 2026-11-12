use tabled::builder::Builder;

use crate::base::diagnostics::print_warning;
use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::heap::{
    BlockMatch, HeapBlock, HeapBlockSearch, HeapDetail, HeapKind, HeapSelector, HeapSummaryDetail,
    NT_ENTRY_EXTRA_PRESENT, NT_ENTRY_FILL_PATTERN, NT_ENTRY_LAST, NT_ENTRY_VIRTUAL_ALLOC, NtEntry,
    NtHeapDetail, RangeKind, SegmentHeapDetail, SegmentRangeDetail, SegmentSubsegment,
};
use crate::session::Session;
use ntoseye_macros::{command, grammar};

/// Summarize, walk, or search the user-mode heaps of the attached process,
/// or of a user-mode minidump's process.
///
/// With no arguments or with -s, the command lists each heap of the process
/// with its kind and sizes: the heaps on ntdll!RtlpProcessHeaps where ntdll
/// keeps that list, else those in the PEB's ProcessHeaps array. -h decodes
/// the segments of one heap, and -a does the
/// same and also lists each entry, chunk, and block. -x finds the block that
/// contains an address, and -p -a does the same search. To identify a heap,
/// use its index in that list or its address. The command decodes NT
/// heaps, including legacy-LFH blocks, and segment heaps, including VS, LFH,
/// page, and large allocations. It gets the encoding keys from ntdll
/// symbols. For NT heaps, it uses _HEAP.Encoding and finds legacy-LFH blocks
/// through their user block regions. For segment heaps, it uses the keys in
/// ntdll!RtlpHpHeapGlobals. In a WOW64 process, the command shows the 32-bit
/// heaps and decodes them with the layouts and keys of ntdll32.
#[command(
    names = ["!heap", "heap"],
    category = "user mode",
    kind = Query,
    target = Nt,
    forms = [inspect_heap, find_block],
)]
fn heap(session: &Session, #[arg(parse = heap_query)] query: HeapQuery) -> Result<HeapReport> {
    let target = &session.target;
    Ok(match query {
        HeapQuery::Summary => HeapReport::Summary(target.heap_summary()?),
        HeapQuery::Detail { heap, entries } => {
            // WinDbg's index-first selection: a value is an index when that
            // index exists, otherwise a heap address.
            let summary = target.heap_summary()?;
            let selector = if usize::try_from(heap.0)
                .ok()
                .is_some_and(|index| summary.heaps.iter().any(|heap| heap.index == index))
            {
                HeapSelector::Index(heap.0 as usize)
            } else {
                HeapSelector::Address(heap)
            };
            HeapReport::Detail(inspect_heap(session, selector, entries)?)
        }
        HeapQuery::Find(address) => HeapReport::Find(find_block(session, address)?),
    })
}

/// Decode this heap (`!heap -h`), with its entries if `list_entries` is
/// true.
#[command(form_of = heap, python = Heap, python_name = "inspect")]
fn inspect_heap(
    session: &Session,
    #[arg(receiver)] heap: HeapSelector,
    #[arg(default = false)] list_entries: bool,
) -> Result<HeapDetail> {
    session.target.inspect_heap(heap, list_entries)
}

/// Find the heap block that contains `address` (`!heap -x`).
#[command(form_of = heap, python = Heaps)]
fn find_block(session: &Session, address: VirtAddr) -> Result<HeapBlockSearch> {
    session.target.find_heap_block(address)
}

/// What `!heap` was asked for, its expressions evaluated.
pub enum HeapQuery {
    Summary,
    Detail { heap: VirtAddr, entries: bool },
    Find(VirtAddr),
}

/// What `!heap` shows: the PEB's heap list, one heap, or a block search.
pub enum HeapReport {
    Summary(HeapSummaryDetail),
    Detail(HeapDetail),
    Find(HeapBlockSearch),
}

impl Render for HeapReport {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Summary(summary) => repl.heap_summary(summary),
            Self::Detail(detail) => repl.heap_detail(detail),
            Self::Find(search) => repl.heap_find(search),
        }
    }
}

#[grammar(
    usage = "[-s] | [-h|-a] <heap> | -x <address> | -p -a <address>",
    complete = [None, Expression]
)]
fn heap_query(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<HeapQuery, ArgError> {
    let mut words = Vec::with_capacity(cursor.remaining());
    while let Some(word) = cursor.word() {
        words.push(word);
    }
    Ok(match parse_request(&words).ok_or(ArgError::Missing)? {
        Request::Summary => HeapQuery::Summary,
        Request::Detail { heap, entries } => HeapQuery::Detail {
            heap: cx.eval(&heap)?,
            entries,
        },
        Request::Find(text) => HeapQuery::Find(cx.eval(&text)?),
    })
}

/// `HEAP_*` creation flags, as `_HEAP.Flags` records them.
const HEAP_FLAG_NAMES: [(u32, &str); 11] = [
    (0x0000_0001, "NO_SERIALIZE"),
    (0x0000_0002, "GROWABLE"),
    (0x0000_0004, "GENERATE_EXCEPTIONS"),
    (0x0000_0008, "ZERO_MEMORY"),
    (0x0000_0010, "REALLOC_IN_PLACE_ONLY"),
    (0x0000_0020, "TAIL_CHECKING_ENABLED"),
    (0x0000_0040, "FREE_CHECKING_ENABLED"),
    (0x0000_0080, "DISABLE_COALESCE_ON_FREE"),
    (0x0001_0000, "CREATE_ALIGN_16"),
    (0x0002_0000, "CREATE_ENABLE_TRACING"),
    (0x0004_0000, "CREATE_ENABLE_EXECUTE"),
];

enum Request {
    Summary,
    Detail { heap: String, entries: bool },
    Find(String),
}

fn parse_request(argv: &[std::borrow::Cow<'_, str>]) -> Option<Request> {
    let mut args = argv.iter().map(|arg| arg.as_ref()).peekable();
    let Some(first) = args.next() else {
        return Some(Request::Summary);
    };
    let request = match first {
        "-s" => Request::Summary,
        "-h" | "-a" => Request::Detail {
            heap: args.next()?.to_string(),
            entries: first == "-a",
        },
        "-x" => Request::Find(args.next()?.to_string()),
        "-p" => {
            if args.next()? != "-a" {
                return None;
            }
            Request::Find(args.next()?.to_string())
        }
        text if !text.starts_with('-') => Request::Detail {
            heap: text.to_string(),
            entries: false,
        },
        _ => return None,
    };
    args.next().is_none().then_some(request)
}

fn flag_names(flags: u32) -> String {
    let names: Vec<&str> = HEAP_FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        format!("{flags:#x}")
    } else {
        format!("{flags:#x} ({})", names.join(" | "))
    }
}

/// `1 segment`, `4 segments`.
fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// `heap 0` or `heaps 0, 2`: the heaps a warning is about, by PEB index.
fn heap_indexes(indexes: &[usize]) -> String {
    let list: Vec<String> = indexes.iter().map(usize::to_string).collect();
    format!(
        "{} {}",
        if indexes.len() == 1 { "heap" } else { "heaps" },
        list.join(", ")
    )
}

/// Groups per-heap failures by their text, in first-seen order, so each
/// distinct reason is reported once with every heap it hit: one missing
/// layout field fails every heap of a kind the same way.
fn group_failures<'a>(
    failures: impl IntoIterator<Item = (usize, &'a str)>,
) -> Vec<(&'a str, Vec<usize>)> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for (index, error) in failures {
        match groups.iter_mut().find(|(text, _)| *text == error) {
            Some((_, indexes)) => indexes.push(index),
            None => groups.push((error, vec![index])),
        }
    }
    groups
}

/// Prints `fields` one per line under a heading, indented `indent` spaces,
/// with each value starting in the column after the longest label.
fn print_fields(indent: usize, fields: &[(&str, String)]) {
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    for (label, value) in fields {
        outln!("{:indent$}{label:<width$}  {value}", "");
    }
}

/// The kind of a heap in prose. An unknown heap's signature is left to the
/// error that reports it.
fn kind_name(kind: &HeapKind) -> &'static str {
    match kind {
        HeapKind::Nt => "NT heap",
        HeapKind::Segment => "segment heap",
        HeapKind::Unknown(_) => "unknown heap",
    }
}

fn state_name(busy: bool) -> &'static str {
    if busy { "busy" } else { "free" }
}

/// The state and header flags of an NT heap entry, such as `busy | extra`,
/// with a badge when the header checksum is wrong.
fn nt_entry_flags(entry: &NtEntry) -> String {
    let mut flags = vec![state_name(entry.busy())];
    if entry.flags & NT_ENTRY_EXTRA_PRESENT != 0 {
        flags.push("extra");
    }
    if entry.flags & NT_ENTRY_FILL_PATTERN != 0 {
        flags.push("fill");
    }
    if entry.flags & NT_ENTRY_VIRTUAL_ALLOC != 0 {
        flags.push("virtual");
    }
    if entry.flags & NT_ENTRY_LAST != 0 {
        flags.push("last");
    }
    let mut text = flags.join(" | ");
    if !entry.checksum_ok {
        text.push_str(&format!("  {}", ui::badge("bad checksum")));
    }
    text
}

// The flags come last in the entry and block lines: their width varies
// the most, and the numeric columns before them stay aligned.
fn nt_entry_line(entry: &NtEntry) -> String {
    format!(
        "{}  size {:<7} prev {:<7} unused {:<6} {}",
        ui::addr(entry.address.0),
        format!("{:#x}", entry.size),
        format!("{:#x}", entry.previous_size),
        format!("{:#x}", entry.unused_bytes),
        nt_entry_flags(entry)
    )
}

fn heap_block_line(block: &HeapBlock) -> String {
    format!(
        "{}  size {:<7} prev {:<7} unused {:<6} {}",
        ui::addr(block.address.0),
        format!("{:#x}", block.size),
        block
            .previous_size
            .map_or_else(|| "-".into(), |size| format!("{size:#x}")),
        block
            .unused_bytes
            .map_or_else(|| "-".into(), |unused| format!("{unused:#x}")),
        block.state
    )
}

/// The fields of an NT heap entry, as `!heap -x` shows them.
fn nt_entry_fields(entry: &NtEntry) -> Vec<(&'static str, String)> {
    vec![
        ("entry", ui::addr(entry.address.0)),
        ("size", format!("{:#x}", entry.size)),
        ("prev size", format!("{:#x}", entry.previous_size)),
        ("unused", format!("{:#x}", entry.unused_bytes)),
        ("flags", nt_entry_flags(entry)),
    ]
}

impl ReplState<'_> {
    fn heap_summary(&self, summary: &HeapSummaryDetail) {
        if summary.truncated {
            print_warning("heap list truncated at the decoder bound");
        }
        // Each statistics error is reported once, with the heaps it hit,
        // rather than repeated in every row: one missing layout field
        // fails every heap of a kind the same way.
        let failures = group_failures(summary.heaps.iter().filter_map(|heap| match &heap.stats {
            DiagnosticValue::Unavailable(error) => Some((heap.index, error.as_str())),
            DiagnosticValue::Available(_) => None,
        }));
        for (error, heaps) in &failures {
            print_warning(format!(
                "{}: statistics unavailable: {error}",
                heap_indexes(heaps)
            ));
        }
        outln!(
            "{}, PEB {}",
            plural(summary.heaps.len() as u64, "process heap", "process heaps"),
            ui::addr(summary.peb.0)
        );
        if summary.heaps.is_empty() {
            return;
        }
        let mut builder = Builder::default();
        builder.push_record([
            "Index",
            "Heap",
            "Kind",
            "Flags",
            "Reserved",
            "Committed",
            "Free",
            "Detail",
        ]);
        for heap in &summary.heaps {
            let row = match &heap.stats {
                DiagnosticValue::Available(stats) => {
                    let detail = match heap.kind {
                        HeapKind::Nt => format!(
                            "{}, {}{}",
                            plural(stats.segments, "segment", "segments"),
                            plural(stats.virtual_blocks, "virtual block", "virtual blocks"),
                            if stats.front_end.is_some() {
                                ", LFH"
                            } else {
                                ""
                            }
                        ),
                        HeapKind::Segment => format!(
                            "{} VS, {} LFH, {} page, {} large",
                            stats.vs_subsegments,
                            stats.lfh_subsegments,
                            stats.page_allocations,
                            stats.large_allocations
                        ),
                        HeapKind::Unknown(_) => "-".into(),
                    };
                    [
                        flag_names(stats.flags),
                        format!("{:#x}", stats.reserved),
                        format!("{:#x}", stats.committed),
                        format!("{:#x}", stats.free),
                        detail,
                    ]
                }
                DiagnosticValue::Unavailable(_) => {
                    ["-".into(), "-".into(), "-".into(), "-".into(), "-".into()]
                }
            };
            let [flags, reserved, committed, free, detail] = row;
            builder.push_record([
                heap.index.to_string(),
                ui::addr(heap.address.0),
                heap.kind.to_string(),
                flags,
                reserved,
                committed,
                free,
                detail,
            ]);
        }
        print_padded_table(builder);
    }

    fn heap_detail(&self, detail: &HeapDetail) {
        if let Some(error) = detail.error.as_deref() {
            error!(
                "heap {} ({} {:#x}) cannot be decoded: {error}",
                detail.index,
                kind_name(&detail.kind),
                detail.address.0
            );
            return;
        }
        match (&detail.nt, &detail.segment) {
            (Some(nt), None) => self.nt_detail(nt, detail.list_entries),
            (None, Some(segment)) => self.segment_detail(segment, detail.list_entries),
            _ => error!(
                "heap {:#x} has no decodable allocator detail",
                detail.address.0
            ),
        }
    }

    fn nt_detail(&self, detail: &NtHeapDetail, list_entries: bool) {
        let heap = &detail.heap;
        outln!("NT heap {}", ui::addr(heap.address.0));
        print_fields(
            2,
            &[
                ("flags", flag_names(heap.flags)),
                ("force flags", format!("{:#x}", heap.force_flags)),
                (
                    "encoding",
                    heap.encoding
                        .map_or_else(|| "-".into(), |encoding| format!("{encoding:#x}")),
                ),
                (
                    "total free",
                    format!("{:#x}", heap.total_free_units.saturating_mul(heap.granule)),
                ),
                (
                    "virtual threshold",
                    format!("{:#x}", heap.virtual_threshold),
                ),
                (
                    "front end",
                    match heap.front_end {
                        Some(lfh) => {
                            format!("LFH {} (type {})", ui::addr(lfh.0), heap.front_end_type)
                        }
                        None => "-".into(),
                    },
                ),
            ],
        );
        print_section("segments");
        let mut builder = Builder::default();
        builder.push_record([
            "Segment",
            "Base",
            "End",
            "Pages",
            "Uncommitted",
            "Ranges",
            "First entry",
            "Last valid entry",
        ]);
        for segment in &detail.segments {
            let segment = &segment.segment;
            builder.push_record([
                ui::addr(segment.address.0),
                ui::addr(segment.base.0),
                ui::addr(segment.end().0),
                format!("{:#x}", segment.pages),
                format!("{:#x}", segment.uncommitted_pages),
                segment.uncommitted.len().to_string(),
                ui::addr(segment.first_entry.0),
                ui::addr(segment.last_valid_entry.0),
            ]);
        }
        // The table ends with a blank line, so the titles after it are
        // printed without print_section's own.
        print_padded_table(builder);
        if !heap.virtual_blocks.is_empty() {
            outln!("{}", ui::label("virtual blocks"));
            let mut builder = Builder::default();
            builder.push_record(["Entry", "Commit", "Reserve", "User"]);
            for block in &heap.virtual_blocks {
                builder.push_record([
                    ui::addr(block.entry.0),
                    format!("{:#x}", block.commit_size),
                    format!("{:#x}", block.reserve_size),
                    ui::addr(block.user.0),
                ]);
            }
            print_padded_table(builder);
        }
        if !list_entries {
            return;
        }
        for segment_detail in &detail.segments {
            let segment = &segment_detail.segment;
            outln!(
                "{}",
                ui::label(&format!(
                    "entries of segment {}",
                    ui::addr(segment.address.0)
                ))
            );
            let (mut busy, mut free) = (0usize, 0usize);
            for entry_detail in &segment_detail.entries {
                let entry = &entry_detail.entry;
                outln!("  {}", nt_entry_line(entry));
                if entry.busy() {
                    busy += 1;
                } else {
                    free += 1;
                }
                if let Some(error) = entry_detail.lfh_error.as_deref() {
                    outln!("    LFH user blocks: -  {}", ui::muted(error));
                }
                if let Some(region) = &entry_detail.lfh {
                    outln!(
                        "    LFH user blocks: subsegment {}  {} x {:#x}  {} busy",
                        ui::addr(region.subsegment.0),
                        region.block_count,
                        region.block_size,
                        region.busy_count()
                    );
                    for block in &entry_detail.lfh_blocks {
                        outln!("      {}  {}", ui::addr(block.address.0), block.state);
                    }
                    if entry_detail.lfh_truncated {
                        outln!("      {}", ui::muted("LFH block listing truncated"));
                    }
                }
            }
            for range in &segment.uncommitted {
                outln!(
                    "  {} - {}  uncommitted",
                    ui::addr(range.start),
                    ui::addr(range.end)
                );
            }
            if let Some(stopped) = &segment_detail.stopped {
                outln!(
                    "  walk stopped at {:#x}: {}",
                    stopped.address.0,
                    stopped.reason
                );
            }
            outln!(
                "  {}: {busy} busy, {free} free",
                plural(segment_detail.entries.len() as u64, "entry", "entries")
            );
            // Apart from the next segment's entries; dropped after the last.
            outln!();
        }
    }

    fn segment_detail(&self, detail: &SegmentHeapDetail, list_entries: bool) {
        let heap = &detail.heap;
        // Guest counters: a corrupt heap must not overflow them.
        let bytes = |pages: u64| pages.saturating_mul(0x1000);
        outln!("segment heap {}", ui::addr(heap.address.0));
        print_fields(
            2,
            &[
                ("global flags", format!("{:#x}", heap.global_flags)),
                ("reserved", format!("{:#x}", bytes(heap.reserved_pages))),
                ("committed", format!("{:#x}", bytes(heap.committed_pages))),
                (
                    "free committed",
                    match heap.vs_free_committed_pages {
                        Some(vs) => format!(
                            "{:#x} (LFH {:#x}, VS {:#x})",
                            bytes(heap.free_committed_pages),
                            bytes(heap.lfh_free_committed_pages),
                            bytes(vs)
                        ),
                        None => format!(
                            "{:#x} (LFH {:#x})",
                            bytes(heap.free_committed_pages),
                            bytes(heap.lfh_free_committed_pages)
                        ),
                    },
                ),
                (
                    "large allocations",
                    format!(
                        "{}{} (reserved {:#x}, committed {:#x})",
                        heap.large_allocations.len(),
                        if heap.large_truncated {
                            "+ (walk limit reached)"
                        } else {
                            ""
                        },
                        bytes(heap.large_reserved_pages),
                        bytes(heap.large_committed_pages)
                    ),
                ),
                ("heap key", format!("{:#x}", heap.encoding_keys.heap_key)),
                ("LFH key", format!("{:#x}", heap.encoding_keys.lfh_key)),
            ],
        );
        for context_detail in &detail.contexts {
            let context = &context_detail.context;
            print_section(&format!("context {}", context.index));
            print_fields(
                2,
                &[
                    ("unit size", format!("{:#x}", context.unit_size())),
                    ("segment size", format!("{:#x}", context.segment_size())),
                    (
                        "max allocation",
                        format!("{:#x}", context.max_allocation_size),
                    ),
                    ("segments", context.segments.len().to_string()),
                ],
            );
            for segment in &context_detail.segments {
                outln!("  segment {}", ui::addr(segment.segment.address.0));
                for range in &segment.ranges {
                    self.segment_range(range, list_entries);
                }
            }
        }
        if !heap.large_allocations.is_empty() {
            print_section("large allocations");
            let mut builder = Builder::default();
            builder.push_record(["Address", "Size", "Unused", "Extra"]);
            for large in &heap.large_allocations {
                builder.push_record([
                    ui::addr(large.address.0),
                    format!("{:#x}", large.size()),
                    format!("{:#x}", large.unused_bytes),
                    if large.extra_present { "yes" } else { "no" }.into(),
                ]);
            }
            print_padded_table(builder);
        }
    }

    fn segment_range(&self, range: &SegmentRangeDetail, list_entries: bool) {
        let range_data = &range.range;
        let head = format!(
            "    {}  {:>10}  {:#04x}",
            ui::addr(range_data.address.0),
            plural(range_data.units, "unit", "units"),
            range_data.flags
        );
        match range_data.kind {
            RangeKind::Unused => outln!("{head}  unused"),
            RangeKind::Free => outln!("{head}  free"),
            RangeKind::Direct => outln!(
                "{head}  page allocation  user {}  unused {:#x}",
                ui::addr(range_data.address.0),
                range_data.unused_bytes
            ),
            RangeKind::Vs => match (&range.subsegment, &range.error) {
                (Some(SegmentSubsegment::Vs(subsegment)), _) => {
                    let busy = subsegment.chunks.iter().filter(|chunk| chunk.busy).count();
                    outln!(
                        "{head}  VS subsegment  {}: {busy} busy, {} free{}",
                        plural(subsegment.chunks.len() as u64, "chunk", "chunks"),
                        subsegment.chunks.len() - busy,
                        if subsegment.signature_ok {
                            String::new()
                        } else {
                            format!("  {}", ui::badge("bad signature"))
                        }
                    );
                    if list_entries {
                        for block in &range.blocks {
                            outln!("      {}", heap_block_line(block));
                        }
                        if range.truncated {
                            outln!("      {}", ui::muted("VS chunk listing truncated"));
                        }
                    }
                }
                (_, Some(error)) => outln!("{head}  VS subsegment  -  {}", ui::muted(error)),
                _ => outln!("{head}  VS subsegment  -"),
            },
            RangeKind::Lfh => match (&range.subsegment, &range.error) {
                (Some(SegmentSubsegment::Lfh(subsegment)), _) => {
                    outln!(
                        "{head}  LFH subsegment  bucket {}: {} x {:#x}, {} busy, {} free",
                        subsegment
                            .bucket
                            .map_or_else(|| "-".into(), |bucket| bucket.to_string()),
                        subsegment.block_count,
                        subsegment.block_size,
                        subsegment.busy_count(),
                        subsegment.free_count
                    );
                    if list_entries {
                        for block in &range.blocks {
                            outln!("      {}  {}", ui::addr(block.address.0), block.state);
                        }
                        if range.truncated {
                            outln!("      {}", ui::muted("LFH block listing truncated"));
                        }
                    }
                }
                (_, Some(error)) => outln!("{head}  LFH subsegment  -  {}", ui::muted(error)),
                _ => outln!("{head}  LFH subsegment  -"),
            },
        }
    }

    fn heap_find(&self, detail: &HeapBlockSearch) {
        // A heap that could not be searched is reported once per reason, as
        // `!heap -s` reports its statistics: the search still answers from
        // the heaps it could read.
        let failures = group_failures(
            detail
                .failures
                .iter()
                .map(|failure| (failure.index, failure.error.as_str())),
        );
        for (error, heaps) in &failures {
            print_warning(format!(
                "{}: cannot be searched: {error}",
                heap_indexes(heaps)
            ));
        }
        if detail.truncated {
            print_warning("heap list truncated at the decoder bound");
        }
        let Some(heap) = &detail.heap else {
            if detail.failures.is_empty() {
                outln!(
                    "{:#x} is not inside any heap of the process",
                    detail.address.0
                );
            } else {
                let unsearched: Vec<usize> = detail
                    .failures
                    .iter()
                    .map(|failure| failure.index)
                    .collect();
                let searched = if detail.searched.is_empty() {
                    "any heap that could be read".to_string()
                } else {
                    heap_indexes(&detail.searched)
                };
                outln!(
                    "{:#x} is not in {searched}; {} could not be searched",
                    detail.address.0,
                    heap_indexes(&unsearched)
                );
            }
            return;
        };
        outln!("heap block containing {}", ui::addr(detail.address.0));
        let mut fields = vec![(
            "heap",
            format!(
                "{} ({}, index {})",
                ui::addr(heap.address.0),
                kind_name(&heap.kind),
                heap.index
            ),
        )];
        if let Some(block) = &detail.block {
            fields.extend(block_fields(block));
        }
        print_fields(2, &fields);
    }
}

/// The fields `!heap -x` shows for the block it found.
fn block_fields(block: &BlockMatch) -> Vec<(&'static str, String)> {
    match block {
        BlockMatch::NtEntry { segment, entry } => {
            let mut fields = vec![("segment", ui::addr(segment.0))];
            fields.extend(nt_entry_fields(entry));
            fields.push(("user", ui::addr(entry.user().0)));
            fields.push(("user size", format!("{:#x}", entry.user_size())));
            fields
        }
        BlockMatch::NtLfhBlock {
            segment,
            entry,
            region,
            index,
        } => {
            let mut fields = vec![("segment", ui::addr(segment.0))];
            fields.extend(nt_entry_fields(entry));
            let block = region.block(*index);
            fields.extend([
                ("LFH user blocks", ui::addr(region.header.0)),
                ("subsegment", ui::addr(region.subsegment.0)),
                (
                    "blocks",
                    format!("{} x {:#x}", region.block_count, region.block_size),
                ),
                ("block", format!("{} (index {index})", ui::addr(block.0))),
                ("state", state_name(region.is_busy(*index)).into()),
                ("user", ui::addr(block.0 + entry.granule)),
            ]);
            fields
        }
        BlockMatch::NtVirtual(block) => vec![
            ("virtual block", ui::addr(block.entry.0)),
            ("commit", format!("{:#x}", block.commit_size)),
            ("reserve", format!("{:#x}", block.reserve_size)),
            ("user", ui::addr(block.user.0)),
        ],
        BlockMatch::NtSegmentOnly { segment, stopped } => vec![
            ("segment", ui::addr(segment.0)),
            (
                "entry",
                match stopped {
                    Some(stop) => format!(
                        "- (not reached: the entry walk stopped at {:#x}: {})",
                        stop.address.0, stop.reason
                    ),
                    None => "- (in an uncommitted range or the segment header)".into(),
                },
            ),
        ],
        BlockMatch::Direct(range) => vec![
            ("page allocation", ui::addr(range.address.0)),
            ("size", format!("{:#x}", range.size())),
            ("unused", format!("{:#x}", range.unused_bytes)),
        ],
        BlockMatch::VsChunk {
            range,
            subsegment,
            chunk,
        } => vec![
            (
                "page range",
                format!(
                    "{} ({})",
                    ui::addr(range.address.0),
                    plural(range.units, "unit", "units")
                ),
            ),
            ("VS subsegment", ui::addr(subsegment.0)),
            ("chunk", ui::addr(chunk.address.0)),
            ("size", format!("{:#x}", chunk.size)),
            ("prev size", format!("{:#x}", chunk.previous_size)),
            (
                "unused",
                chunk
                    .unused_bytes
                    .map_or_else(|| "-".into(), |unused| format!("{unused:#x}")),
            ),
            ("state", state_name(chunk.busy).into()),
            ("user", ui::addr(chunk.user().0)),
            ("user size", format!("{:#x}", chunk.user_size())),
        ],
        BlockMatch::LfhBlock {
            range,
            subsegment,
            index,
        } => vec![
            (
                "page range",
                format!(
                    "{} ({})",
                    ui::addr(range.address.0),
                    plural(range.units, "unit", "units")
                ),
            ),
            ("LFH subsegment", ui::addr(subsegment.address.0)),
            (
                "bucket",
                subsegment
                    .bucket
                    .map_or_else(|| "-".into(), |bucket| bucket.to_string()),
            ),
            (
                "blocks",
                format!("{} x {:#x}", subsegment.block_count, subsegment.block_size),
            ),
            (
                "block",
                format!("{} (index {index})", ui::addr(subsegment.block(*index).0)),
            ),
            ("state", state_name(subsegment.is_busy(*index)).into()),
        ],
        BlockMatch::RangeOnly(range) => vec![
            (
                "page range",
                format!(
                    "{} ({})",
                    ui::addr(range.address.0),
                    plural(range.units, "unit", "units")
                ),
            ),
            ("flags", format!("{:#04x}", range.flags)),
            (
                "state",
                match range.kind {
                    RangeKind::Free => "free",
                    RangeKind::Unused => "unused",
                    _ => "outside the subsegment's blocks (header, bitmap, or slack)",
                }
                .into(),
            ),
        ],
        BlockMatch::Large(large) => vec![
            ("large allocation", ui::addr(large.address.0)),
            (
                "size",
                format!(
                    "{:#x} ({})",
                    large.size(),
                    plural(large.pages, "page", "pages")
                ),
            ),
            ("unused", format!("{:#x}", large.unused_bytes)),
            ("metadata", ui::addr(large.metadata.0)),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn parse(args: &[&str]) -> Option<Request> {
        let argv: Vec<Cow<'_, str>> = args.iter().map(|arg| Cow::Borrowed(*arg)).collect();
        parse_request(&argv)
    }

    #[test]
    fn request_forms_follow_windbg() {
        assert!(matches!(parse(&[]), Some(Request::Summary)));
        assert!(matches!(parse(&["-s"]), Some(Request::Summary)));
        assert!(matches!(
            parse(&["0"]),
            Some(Request::Detail { heap, entries: false }) if heap == "0"
        ));
        assert!(matches!(
            parse(&["-h", "0x1190000"]),
            Some(Request::Detail { heap, entries: false }) if heap == "0x1190000"
        ));
        assert!(matches!(
            parse(&["-a", "0"]),
            Some(Request::Detail { heap, entries: true }) if heap == "0"
        ));
        assert!(matches!(
            parse(&["-x", "@rcx"]),
            Some(Request::Find(text)) if text == "@rcx"
        ));
        assert!(matches!(
            parse(&["-p", "-a", "@rcx"]),
            Some(Request::Find(text)) if text == "@rcx"
        ));
        for bad in [
            &["-h"][..],
            &["-p", "@rcx"],
            &["-x"],
            &["-z"],
            &["0", "1"],
            &["-s", "extra"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
