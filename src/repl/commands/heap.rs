use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::DiagnosticValue;
use crate::target::heap::{
    BlockMatch, HeapBlock, HeapBlockSearch, HeapDetail, HeapKind, HeapSelector, HeapSummaryDetail,
    NT_ENTRY_EXTRA_PRESENT, NT_ENTRY_FILL_PATTERN, NT_ENTRY_LAST, NT_ENTRY_VIRTUAL_ALLOC, NtEntry,
    NtHeapDetail, RangeKind, SegmentHeapDetail, SegmentRangeDetail, SegmentSubsegment, VsChunk,
};
use crate::types::VirtAddr;
use crate::ui;
use ntoseye_macros::command;

/// Summarize, walk, or search the user-mode heaps of the attached process,
/// or of a user-mode minidump's process.
///
/// With no arguments or with -s, the command lists each heap in the PEB with
/// its kind and sizes. -h decodes the segments of one heap, and -a does the
/// same and also lists each entry, chunk, and block. -x finds the block that
/// contains an address, and -p -a does the same search. To identify a heap,
/// use its index in the PEB list or its address. The command decodes NT
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
    forms = [inspect_heap, find_block],
    usage = "!heap [-s] [-h|-a <heap>] [-x <address>] [-p -a <address>]",
    completion = [None, Expression]
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
#[command(form_of = heap, python = Heap, python_name = "inspect", sdk)]
fn inspect_heap(
    session: &Session,
    #[arg(receiver)] heap: HeapSelector,
    #[arg(default = false)] list_entries: bool,
) -> Result<HeapDetail> {
    session.target.inspect_heap(heap, list_entries)
}

/// Find the heap block that contains `addr` (`!heap -x`).
#[command(form_of = heap, python = Heaps, word = "-x")]
fn find_block(
    session: &Session,
    #[arg(name = "address", complete = Expression)] addr: VirtAddr,
) -> Result<HeapBlockSearch> {
    session.target.find_heap_block(addr)
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
        format!("{flags:#x} ({})", names.join("|"))
    }
}

fn nt_entry_line(entry: &NtEntry) -> String {
    let mut flags = Vec::new();
    if entry.busy() {
        flags.push("busy");
    } else {
        flags.push("free");
    }
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
    let mut line = format!(
        "{}  size {:<7} prev {:<7} {:<10} unused {:#x}",
        ui::addr(entry.address.0),
        format!("{:#x}", entry.size),
        format!("{:#x}", entry.previous_size),
        flags.join("|"),
        entry.unused_bytes
    );
    if !entry.checksum_ok {
        line.push_str(&format!("  {}", ui::badge("bad checksum")));
    }
    line
}

fn vs_chunk_line(chunk: &VsChunk) -> String {
    let mut line = format!(
        "{}  size {:<7} prev {:<7} {}",
        ui::addr(chunk.address.0),
        format!("{:#x}", chunk.size),
        format!("{:#x}", chunk.previous_size),
        if chunk.busy { "busy" } else { "free" }
    );
    if let Some(unused) = chunk.unused_bytes {
        line.push_str(&format!("  unused {unused:#x}"));
    }
    line
}

fn heap_block_line(block: &HeapBlock) -> String {
    let mut line = format!(
        "{}  size {:<7}",
        ui::addr(block.address.0),
        format!("{:#x}", block.size)
    );
    if let Some(previous_size) = block.previous_size {
        line.push_str(&format!("  prev {:<7}", format!("{previous_size:#x}")));
    }
    line.push_str(&format!("  {}", block.state));
    if let Some(unused_bytes) = block.unused_bytes {
        line.push_str(&format!("  unused {unused_bytes:#x}"));
    }
    line
}

impl ReplState<'_> {
    fn heap_summary(&self, summary: &HeapSummaryDetail) {
        outln!(
            "{} process heap(s), PEB {}",
            summary.heaps.len(),
            ui::addr(summary.peb.0)
        );
        if summary.truncated {
            outln!("heap list truncated at the decoder bound");
        }
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
                            "{} segment(s), {} virtual block(s){}",
                            stats.segments,
                            stats.virtual_blocks,
                            if stats.front_end.is_some() {
                                ", LFH"
                            } else {
                                ""
                            }
                        ),
                        HeapKind::Segment => format!(
                            "{} vs, {} lfh, {} page, {} large",
                            stats.vs_subsegments,
                            stats.lfh_subsegments,
                            stats.page_allocations,
                            stats.large_allocations
                        ),
                        HeapKind::Unknown(_) => String::new(),
                    };
                    [
                        format!("{:#x}", stats.flags),
                        format!("{:#x}", stats.reserved),
                        format!("{:#x}", stats.committed),
                        format!("{:#x}", stats.free),
                        detail,
                    ]
                }
                DiagnosticValue::Unavailable(error) => [
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    format!("<unavailable: {error}>"),
                ],
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
            error!("{error}");
            return;
        }
        match (&detail.nt, &detail.segment) {
            (Some(nt), None) => self.nt_detail(nt, detail.list_entries),
            (None, Some(segment)) => self.segment_detail(segment, detail.list_entries),
            _ => error!(
                "heap {} has no decodable allocator detail",
                ui::addr(detail.address.0)
            ),
        }
    }

    fn nt_detail(&self, detail: &NtHeapDetail, list_entries: bool) {
        let heap = &detail.heap;
        outln!("heap {}: NT heap", ui::addr(heap.address.0));
        outln!(
            "  flags {}  force flags {:#x}  encoding {}",
            flag_names(heap.flags),
            heap.force_flags,
            heap.encoding
                .map(|encoding| format!("{encoding:#x}"))
                .unwrap_or_else(|| "off".into())
        );
        outln!(
            "  total free {:#x}  virtual threshold {:#x}  front end {}",
            heap.total_free_units * 16,
            heap.virtual_threshold,
            match heap.front_end {
                Some(lfh) => format!("LFH {} (type {})", ui::addr(lfh.0), heap.front_end_type),
                None => "none".into(),
            }
        );
        let mut builder = Builder::default();
        builder.push_record([
            "Segment",
            "Base",
            "End",
            "Pages",
            "Uncommitted",
            "FirstEntry",
            "LastValidEntry",
        ]);
        for segment in &detail.segments {
            let segment = &segment.segment;
            builder.push_record([
                ui::addr(segment.address.0),
                ui::addr(segment.base.0),
                ui::addr(segment.end().0),
                format!("{:#x}", segment.pages),
                format!(
                    "{:#x} ({} range(s))",
                    segment.uncommitted_pages,
                    segment.uncommitted.len()
                ),
                ui::addr(segment.first_entry.0),
                ui::addr(segment.last_valid_entry.0),
            ]);
        }
        print_padded_table(builder);
        if !heap.virtual_blocks.is_empty() {
            outln!("  virtual blocks:");
            for block in &heap.virtual_blocks {
                outln!(
                    "    {}  commit {:#x}  reserve {:#x}  user {}",
                    ui::addr(block.entry.0),
                    block.commit_size,
                    block.reserve_size,
                    ui::addr(block.user.0)
                );
            }
        }
        if !list_entries {
            return;
        }
        for segment_detail in &detail.segments {
            let segment = &segment_detail.segment;
            outln!("  segment {} entries:", ui::addr(segment.address.0));
            let (mut busy, mut free) = (0usize, 0usize);
            for entry_detail in &segment_detail.entries {
                let entry = &entry_detail.entry;
                outln!("    {}", nt_entry_line(entry));
                if entry.busy() {
                    busy += 1;
                } else {
                    free += 1;
                }
                if let Some(error) = entry_detail.lfh_error.as_deref() {
                    outln!("      LFH user blocks: <unavailable: {error}>");
                }
                if let Some(region) = &entry_detail.lfh {
                    outln!(
                        "      LFH user blocks: subsegment {}  {} x {:#x}  {} busy",
                        ui::addr(region.subsegment.0),
                        region.block_count,
                        region.block_size,
                        region.busy_count()
                    );
                    for block in &entry_detail.lfh_blocks {
                        outln!("        {}  {}", ui::addr(block.address.0), block.state);
                    }
                    if entry_detail.lfh_truncated {
                        outln!("        <LFH block listing truncated>");
                    }
                }
            }
            for range in &segment.uncommitted {
                outln!(
                    "    {} - {}  uncommitted",
                    ui::addr(range.start),
                    ui::addr(range.end)
                );
            }
            if let Some(stopped) = &segment_detail.stopped {
                outln!(
                    "    walk stopped at {}: {}",
                    ui::addr(stopped.address.0),
                    stopped.reason
                );
            }
            outln!(
                "    {} entries: {busy} busy, {free} free",
                segment_detail.entries.len()
            );
        }
    }

    fn segment_detail(&self, detail: &SegmentHeapDetail, list_entries: bool) {
        let heap = &detail.heap;
        outln!("heap {}: segment heap", ui::addr(heap.address.0));
        outln!(
            "  global flags {:#x}  reserved {:#x}  committed {:#x}  free committed {:#x} (lfh {:#x}, vs {:#x})",
            heap.global_flags,
            heap.reserved_pages * 0x1000,
            heap.committed_pages * 0x1000,
            heap.free_committed_pages * 0x1000,
            heap.lfh_free_committed_pages * 0x1000,
            heap.vs_free_committed_pages * 0x1000
        );
        outln!(
            "  large allocations {} (reserved {:#x}, committed {:#x})  keys heap {:#x} lfh {:#x}",
            heap.large_allocations.len(),
            heap.large_reserved_pages * 0x1000,
            heap.large_committed_pages * 0x1000,
            heap.encoding_keys.heap_key,
            heap.encoding_keys.lfh_key
        );
        for context_detail in &detail.contexts {
            let context = &context_detail.context;
            outln!(
                "  context {}: {:#x}-byte units, {:#x}-byte segments, max allocation {:#x}, {} segment(s)",
                context.index,
                context.unit_size(),
                context.segment_size(),
                context.max_allocation_size,
                context.segments.len()
            );
            for segment in &context_detail.segments {
                outln!("    segment {}", ui::addr(segment.segment.address.0));
                for range in &segment.ranges {
                    self.segment_range(range, list_entries);
                }
            }
        }
        if !heap.large_allocations.is_empty() {
            outln!("  large allocations:");
            for large in &heap.large_allocations {
                outln!(
                    "    {}  size {:#x}  unused {:#x}{}",
                    ui::addr(large.address.0),
                    large.size(),
                    large.unused_bytes,
                    if large.extra_present { "  extra" } else { "" }
                );
            }
        }
    }

    fn segment_range(&self, range: &SegmentRangeDetail, list_entries: bool) {
        let range_data = &range.range;
        let head = format!(
            "      {}  {:>4} unit(s)  {:#04x}",
            ui::addr(range_data.address.0),
            range_data.units,
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
                        "{head}  VS subsegment  {} chunk(s): {busy} busy, {} free{}",
                        subsegment.chunks.len(),
                        subsegment.chunks.len() - busy,
                        if subsegment.signature_ok {
                            ""
                        } else {
                            "  (bad signature)"
                        }
                    );
                    if list_entries {
                        for block in &range.blocks {
                            outln!("        {}", heap_block_line(block));
                        }
                        if range.truncated {
                            outln!("        <VS chunk listing truncated>");
                        }
                    }
                }
                (_, Some(error)) => outln!("{head}  VS subsegment  <unavailable: {error}>"),
                _ => outln!("{head}  VS subsegment  <unavailable>"),
            },
            RangeKind::Lfh => match (&range.subsegment, &range.error) {
                (Some(SegmentSubsegment::Lfh(subsegment)), _) => {
                    outln!(
                        "{head}  LFH subsegment  bucket {}: {} x {:#x}, {} busy, {} free",
                        subsegment.bucket,
                        subsegment.block_count,
                        subsegment.block_size,
                        subsegment.busy_count(),
                        subsegment.free_count
                    );
                    if list_entries {
                        for block in &range.blocks {
                            outln!("        {}  {}", ui::addr(block.address.0), block.state);
                        }
                        if range.truncated {
                            outln!("        <LFH block listing truncated>");
                        }
                    }
                }
                (_, Some(error)) => outln!("{head}  LFH subsegment  <unavailable: {error}>"),
                _ => outln!("{head}  LFH subsegment  <unavailable>"),
            },
        }
    }

    fn heap_find(&self, detail: &HeapBlockSearch) {
        for error in &detail.errors {
            error!("{error}");
        }
        if detail.truncated {
            error!("heap list truncated at the decoder bound");
        }
        let Some(heap) = &detail.heap else {
            outln!(
                "{} is not inside any heap in the PEB list",
                ui::addr(detail.address.0)
            );
            return;
        };
        outln!(
            "{} is in heap {} ({} heap, index {})",
            ui::addr(detail.address.0),
            ui::addr(heap.address.0),
            heap.kind,
            heap.index
        );
        if let Some(block) = &detail.block {
            print_block(block);
        }
    }
}

fn print_block(block: &BlockMatch) {
    match block {
        BlockMatch::NtEntry { segment, entry } => {
            outln!("  segment {}", ui::addr(segment.0));
            outln!("  {}", nt_entry_line(entry));
            outln!(
                "  user {}  user size {:#x}",
                ui::addr(entry.user().0),
                entry.user_size()
            );
        }
        BlockMatch::NtLfhBlock {
            segment,
            entry,
            region,
            index,
        } => {
            outln!("  segment {}", ui::addr(segment.0));
            outln!("  {}", nt_entry_line(entry));
            outln!(
                "  LFH user blocks {}  subsegment {}  {} x {:#x}",
                ui::addr(region.header.0),
                ui::addr(region.subsegment.0),
                region.block_count,
                region.block_size
            );
            let block = region.block(*index);
            outln!(
                "  block {index}: {}  {}  user {}",
                ui::addr(block.0),
                if region.is_busy(*index) {
                    "busy"
                } else {
                    "free"
                },
                ui::addr(block.0 + entry.granule)
            );
        }
        BlockMatch::NtVirtual(block) => {
            outln!(
                "  virtual block {}  commit {:#x}  reserve {:#x}  user {}",
                ui::addr(block.entry.0),
                block.commit_size,
                block.reserve_size,
                ui::addr(block.user.0)
            );
        }
        BlockMatch::NtSegmentOnly { segment, stopped } => {
            outln!("  segment {}", ui::addr(segment.0));
            match stopped {
                Some(stop) => outln!(
                    "  not reached: the entry walk stopped at {}: {reason}",
                    ui::addr(stop.address.0),
                    reason = stop.reason
                ),
                None => outln!("  in an uncommitted range or the segment header"),
            }
        }
        BlockMatch::Direct(range) => {
            outln!(
                "  page allocation {}  size {:#x}  unused {:#x}",
                ui::addr(range.address.0),
                range.size(),
                range.unused_bytes
            );
        }
        BlockMatch::VsChunk {
            range,
            subsegment,
            chunk,
        } => {
            outln!(
                "  page range {} ({} unit(s)), VS subsegment {}",
                ui::addr(range.address.0),
                range.units,
                ui::addr(subsegment.0)
            );
            outln!("  {}", vs_chunk_line(chunk));
            outln!(
                "  user {}  user size {:#x}",
                ui::addr(chunk.user().0),
                chunk.user_size()
            );
        }
        BlockMatch::LfhBlock {
            range,
            subsegment,
            index,
        } => {
            outln!(
                "  page range {} ({} unit(s)), LFH subsegment {}  bucket {}: {} x {:#x}",
                ui::addr(range.address.0),
                range.units,
                ui::addr(subsegment.address.0),
                subsegment.bucket,
                subsegment.block_count,
                subsegment.block_size
            );
            outln!(
                "  block {index}: {}  {}",
                ui::addr(subsegment.block(*index).0),
                if subsegment.is_busy(*index) {
                    "busy"
                } else {
                    "free"
                }
            );
        }
        BlockMatch::RangeOnly(range) => {
            outln!(
                "  page range {} ({} unit(s), flags {:#04x}): {}",
                ui::addr(range.address.0),
                range.units,
                range.flags,
                match range.kind {
                    RangeKind::Free => "free",
                    RangeKind::Unused => "unused",
                    _ => "outside the subsegment's blocks (header, bitmap, or slack)",
                }
            );
        }
        BlockMatch::Large(large) => {
            outln!(
                "  large allocation {}  size {:#x} ({:#x} pages)  unused {:#x}  metadata {}",
                ui::addr(large.address.0),
                large.size(),
                large.pages,
                large.unused_bytes,
                ui::addr(large.metadata.0)
            );
        }
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
            Some(Request::Detail { entries: false, .. })
        ));
        assert!(matches!(
            parse(&["-h", "0x1190000"]),
            Some(Request::Detail { entries: false, .. })
        ));
        assert!(matches!(
            parse(&["-a", "0"]),
            Some(Request::Detail { entries: true, .. })
        ));
        assert!(matches!(parse(&["-x", "@rcx"]), Some(Request::Find(_))));
        assert!(matches!(
            parse(&["-p", "-a", "@rcx"]),
            Some(Request::Find(_))
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
