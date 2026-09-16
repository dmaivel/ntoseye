use tabled::builder::Builder;

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::types::VirtAddr;
use crate::ui;

use super::usermode::{attached_dtb, resolve_peb};

repl_command! {
    cmd_heap;
    names: ["!heap", "heap"],
    usage: "!heap [-s] [-h|-a <heap>] [-x <address>] [-p -a <address>]",
    summary: "Summarize, walk, or search the attached process's user-mode heaps.",
    details: "Without arguments (or with -s) lists every heap in the PEB with its kind and sizes. -h decodes one heap's segments; -a also lists every entry, chunk, and block. -x finds the block containing an address; -p -a is the same search. A heap is named by its index in the list or its address. NT heaps (including legacy-LFH blocks) and segment heaps (VS, LFH, page, and large allocations) are decoded; ntdll symbols supply the encoding keys.",
    completion: [None, Expression],
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

fn kind_name(kind: HeapKind) -> String {
    match kind {
        HeapKind::Nt => "nt".into(),
        HeapKind::Segment => "segment".into(),
        HeapKind::Unknown(signature) => format!("unknown ({signature:#x})"),
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

impl ReplState<'_> {
    fn cmd_heap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(request) = parse_request(&invocation.argv) else {
            outln!("{}\n", command_help("!heap"));
            return Ok(());
        };
        let dtb = match attached_dtb(&self.ctx.target) {
            Ok(dtb) => dtb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let peb = match resolve_peb(&self.ctx.target, dtb, None) {
            Ok(peb) => peb,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let reader = HeapReader::new(&self.ctx.target, dtb);
        let heaps = match reader.process_heaps(peb) {
            Ok(heaps) => heaps,
            Err(error) => {
                error!("failed to read the PEB heap list: {error}");
                return Ok(());
            }
        };
        match request {
            Request::Summary => self.heap_summary(&reader, peb, &heaps),
            Request::Detail { heap, entries } => {
                let Some(heap) = self.select_heap(&heaps, &heap) else {
                    return Ok(());
                };
                self.heap_detail(&reader, heap, entries)
            }
            Request::Find(text) => {
                let address = match Expr::eval_with_radix(&text, &self.ctx.target, self.radix) {
                    Ok(address) => address,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                };
                self.heap_find(&reader, &heaps, address)
            }
        }
    }

    /// A heap named by its PEB index or its address.
    fn select_heap(&self, heaps: &[ProcessHeap], text: &str) -> Option<ProcessHeap> {
        let value = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(value) => value.0,
            Err(error) => {
                error!("{error}");
                return None;
            }
        };
        if let Some(heap) = usize::try_from(value)
            .ok()
            .and_then(|index| heaps.get(index))
        {
            return Some(*heap);
        }
        if let Some(heap) = heaps.iter().find(|heap| heap.address.0 == value) {
            return Some(*heap);
        }
        error!(
            "{} is neither a heap index (0..{}) nor a heap in the PEB list",
            ui::addr(value),
            heaps.len()
        );
        None
    }

    fn heap_summary(
        &self,
        reader: &HeapReader<'_>,
        peb: VirtAddr,
        heaps: &[ProcessHeap],
    ) -> Result<()> {
        outln!("{} process heap(s), PEB {}", heaps.len(), ui::addr(peb.0));
        if heaps.is_empty() {
            return Ok(());
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
        for heap in heaps {
            let row = match heap.kind {
                HeapKind::Nt => match reader.nt_heap(heap.address) {
                    Ok(nt) => {
                        let reserved: u64 = nt
                            .segments
                            .iter()
                            .map(|s| u64::from(s.pages) * 0x1000)
                            .sum();
                        let uncommitted: u64 = nt
                            .segments
                            .iter()
                            .map(|s| u64::from(s.uncommitted_pages) * 0x1000)
                            .sum();
                        [
                            format!("{:#x}", nt.flags),
                            format!("{reserved:#x}"),
                            format!("{:#x}", reserved - uncommitted),
                            format!("{:#x}", nt.total_free_units * 16),
                            format!(
                                "{} segment(s), {} virtual block(s){}",
                                nt.segments.len(),
                                nt.virtual_blocks.len(),
                                if nt.front_end.is_some() { ", LFH" } else { "" }
                            ),
                        ]
                    }
                    Err(error) => [
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        format!("<unavailable: {error}>"),
                    ],
                },
                HeapKind::Segment => match reader.segment_heap(heap.address) {
                    Ok(segment) => {
                        let subsegments = |kind: RangeKind| {
                            segment
                                .contexts
                                .iter()
                                .flat_map(|context| &context.segments)
                                .flat_map(|segment| &segment.ranges)
                                .filter(|range| range.kind == kind)
                                .count()
                        };
                        [
                            format!("{:#x}", segment.global_flags),
                            format!("{:#x}", segment.reserved_pages * 0x1000),
                            format!("{:#x}", segment.committed_pages * 0x1000),
                            format!("{:#x}", segment.free_committed_pages * 0x1000),
                            format!(
                                "{} vs, {} lfh, {} page, {} large",
                                subsegments(RangeKind::Vs),
                                subsegments(RangeKind::Lfh),
                                subsegments(RangeKind::Direct),
                                segment.large_allocations.len()
                            ),
                        ]
                    }
                    Err(error) => [
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        "-".into(),
                        format!("<unavailable: {error}>"),
                    ],
                },
                HeapKind::Unknown(_) => [
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    String::new(),
                ],
            };
            let [flags, reserved, committed, free, detail] = row;
            builder.push_record([
                heap.index.to_string(),
                ui::addr(heap.address.0),
                kind_name(heap.kind),
                flags,
                reserved,
                committed,
                free,
                detail,
            ]);
        }
        print_padded_table(builder);
        Ok(())
    }

    fn heap_detail(&self, reader: &HeapReader<'_>, heap: ProcessHeap, entries: bool) -> Result<()> {
        match heap.kind {
            HeapKind::Nt => {
                let nt = match reader.nt_heap(heap.address) {
                    Ok(nt) => nt,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                };
                self.nt_detail(reader, &nt, entries)
            }
            HeapKind::Segment => {
                let segment = match reader.segment_heap(heap.address) {
                    Ok(segment) => segment,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                };
                self.segment_detail(reader, &segment, entries)
            }
            HeapKind::Unknown(signature) => {
                error!(
                    "heap {} carries neither heap signature (found {signature:#x})",
                    ui::addr(heap.address.0)
                );
                Ok(())
            }
        }
    }

    fn nt_detail(&self, reader: &HeapReader<'_>, heap: &NtHeap, entries: bool) -> Result<()> {
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
        for segment in &heap.segments {
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
        if !entries {
            return Ok(());
        }
        for segment in &heap.segments {
            outln!("  segment {} entries:", ui::addr(segment.address.0));
            let walk = reader.nt_segment_entries(heap, segment);
            let (mut busy, mut free) = (0usize, 0usize);
            for entry in &walk.entries {
                outln!("    {}", nt_entry_line(entry));
                if entry.busy() {
                    busy += 1;
                } else {
                    free += 1;
                }
                if let Ok(Some(region)) = reader.nt_user_blocks(heap, entry) {
                    outln!(
                        "      LFH user blocks: subsegment {}  {} x {:#x}  {} busy",
                        ui::addr(region.subsegment.0),
                        region.block_count,
                        region.block_size,
                        region.busy_count()
                    );
                    for index in 0..region.block_count {
                        outln!(
                            "        {}  {}",
                            ui::addr(region.block(index).0),
                            if region.is_busy(index) {
                                "busy"
                            } else {
                                "free"
                            }
                        );
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
            if let Some((address, reason)) = walk.stopped {
                outln!("    walk stopped at {}: {reason}", ui::addr(address.0));
            }
            outln!(
                "    {} entries: {busy} busy, {free} free",
                walk.entries.len()
            );
        }
        Ok(())
    }

    fn segment_detail(
        &self,
        reader: &HeapReader<'_>,
        heap: &SegmentHeap,
        entries: bool,
    ) -> Result<()> {
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
            heap.keys.heap_key,
            heap.keys.lfh_key
        );
        for context in &heap.contexts {
            outln!(
                "  context {}: {:#x}-byte units, {:#x}-byte segments, max allocation {:#x}, {} segment(s)",
                context.index,
                context.unit_size(),
                context.segment_size(),
                context.max_allocation_size,
                context.segments.len()
            );
            for segment in &context.segments {
                outln!("    segment {}", ui::addr(segment.address.0));
                for range in &segment.ranges {
                    self.segment_range(reader, heap, range, entries);
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
        Ok(())
    }

    fn segment_range(
        &self,
        reader: &HeapReader<'_>,
        heap: &SegmentHeap,
        range: &PageRange,
        entries: bool,
    ) {
        let head = format!(
            "      {}  {:>4} unit(s)  {:#04x}",
            ui::addr(range.address.0),
            range.units,
            range.flags
        );
        match range.kind {
            RangeKind::Unused => outln!("{head}  unused"),
            RangeKind::Free => outln!("{head}  free"),
            RangeKind::Direct => outln!(
                "{head}  page allocation  user {}  unused {:#x}",
                ui::addr(range.address.0),
                range.unused_bytes
            ),
            RangeKind::Vs => match reader.vs_subsegment(heap, range) {
                Ok(subsegment) => {
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
                    if entries {
                        for chunk in &subsegment.chunks {
                            outln!("        {}", vs_chunk_line(chunk));
                        }
                    }
                }
                Err(error) => outln!("{head}  VS subsegment  <unavailable: {error}>"),
            },
            RangeKind::Lfh => match reader.lfh_subsegment(heap, range) {
                Ok(subsegment) => {
                    outln!(
                        "{head}  LFH subsegment  bucket {}: {} x {:#x}, {} busy, {} free",
                        subsegment.bucket,
                        subsegment.block_count,
                        subsegment.block_size,
                        subsegment.busy_count(),
                        subsegment.free_count
                    );
                    if entries {
                        for index in 0..subsegment.block_count {
                            outln!(
                                "        {}  {}",
                                ui::addr(subsegment.block(index).0),
                                if subsegment.is_busy(index) {
                                    "busy"
                                } else {
                                    "free"
                                }
                            );
                        }
                    }
                }
                Err(error) => outln!("{head}  LFH subsegment  <unavailable: {error}>"),
            },
        }
    }

    fn heap_find(
        &self,
        reader: &HeapReader<'_>,
        heaps: &[ProcessHeap],
        address: VirtAddr,
    ) -> Result<()> {
        for heap in heaps {
            let found = match heap.kind {
                HeapKind::Nt => {
                    let nt = match reader.nt_heap(heap.address) {
                        Ok(nt) => nt,
                        Err(error) => {
                            error!("heap {}: {error}", ui::addr(heap.address.0));
                            continue;
                        }
                    };
                    reader.find_in_nt(&nt, address)
                }
                HeapKind::Segment => {
                    let segment = match reader.segment_heap(heap.address) {
                        Ok(segment) => segment,
                        Err(error) => {
                            error!("heap {}: {error}", ui::addr(heap.address.0));
                            continue;
                        }
                    };
                    reader.find_in_segment(&segment, address)
                }
                HeapKind::Unknown(_) => Ok(None),
            };
            let block = match found {
                Ok(Some(block)) => block,
                Ok(None) => continue,
                Err(error) => {
                    error!("heap {}: {error}", ui::addr(heap.address.0));
                    continue;
                }
            };
            outln!(
                "{} is in heap {} ({} heap, index {})",
                ui::addr(address.0),
                ui::addr(heap.address.0),
                kind_name(heap.kind),
                heap.index
            );
            print_block(&block);
            return Ok(());
        }
        outln!(
            "{} is not inside any heap in the PEB list",
            ui::addr(address.0)
        );
        Ok(())
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
                ui::addr(block.0 + 0x10)
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
                Some((address, reason)) => outln!(
                    "  not reached: the entry walk stopped at {}: {reason}",
                    ui::addr(address.0)
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
