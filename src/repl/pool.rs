use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::symbols::{ParsedType, TypeInfo, format_symbol_with_offset};
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

pub const POOL_ALIGN: u64 = 0x10;

pub const POOL_PAGE_SIZE: u64 = 0x1000;

pub const POOL_FREE_TAG: u32 = 0x6565_7246;

pub const POOL_MAX_GAP_UNITS: u64 = 4;

#[derive(Clone, Copy)]
pub struct PoolHeader {
    header: VirtAddr,
    body: VirtAddr,
    size: u64,
    previous_size: u64,
    pool_type: u8,
    tag: u32,
    synthetic_free: bool,
}

pub struct BigPoolEntry {
    va: VirtAddr,
    entry: VirtAddr,
    index: u64,
    nonpaged: bool,
    size: u64,
    tag: u32,
    pattern: u8,
    pool_flags: u16,
    slush_size: u16,
}

/// PDB-driven layout for `_POOL_HEADER` and `_POOL_TRACKER_BIG_PAGES`. Field
/// presence varies across Windows builds; the `*_uses_struct` flags say whether
/// we can decode each entry field-by-field or have to fall back to fixed offsets
pub struct PoolLayout {
    pool_header: TypeInfo,
    header_size: u64,
    pool_tag_offset: u64,
    pool_header_uses_struct: bool,
    big_pool_type: Option<TypeInfo>,
    big_pool_uses_struct: bool,
    big_pool_has_pool_type: bool,
    big_pool_has_slush: bool,
    big_pool_entry_size: Option<u64>,
}

pub fn pool_layout(debugger: &Target) -> Result<PoolLayout> {
    let pool_header = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_HEADER")
        .ok_or_else(|| Error::StructNotFound("_POOL_HEADER".to_string()))?;
    let pool_tag_offset = pool_header.field_offset("PoolTag")?;
    let pool_header_uses_struct = [
        "PreviousSize",
        "PoolIndex",
        "BlockSize",
        "PoolType",
        "PoolTag",
    ]
    .iter()
    .all(|name| pool_header.fields.contains_key(*name));

    let big_pool_type = debugger
        .symbols
        .find_type_across_modules(debugger.current_dtb(), "_POOL_TRACKER_BIG_PAGES");
    let (big_pool_uses_struct, big_pool_has_pool_type, big_pool_has_slush) = match &big_pool_type {
        Some(ti) => (
            ["Va", "Key", "NumberOfBytes", "Pattern"]
                .iter()
                .all(|name| ti.fields.contains_key(*name)),
            ti.fields.contains_key("PoolType"),
            ti.fields.contains_key("SlushSize"),
        ),
        None => (false, false, false),
    };
    let big_pool_entry_size = big_pool_type.as_ref().map(|ti| ti.size as u64);

    Ok(PoolLayout {
        header_size: pool_header.size as u64,
        pool_header,
        pool_tag_offset,
        pool_header_uses_struct,
        big_pool_type,
        big_pool_uses_struct,
        big_pool_has_pool_type,
        big_pool_has_slush,
        big_pool_entry_size,
    })
}

pub fn read_pool_field(
    ti: &TypeInfo,
    mem: &impl MemoryOps<VirtAddr>,
    addr: VirtAddr,
    field: &str,
) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let field_addr = addr + f.offset as u64;
    if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
        let raw: u64 = mem.read(field_addr).ok()?;
        let mask = if *len == 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        return Some((raw >> *pos) & mask);
    }

    match field {
        "PreviousSize" | "PoolIndex" | "BlockSize" | "PoolType" | "Pattern" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u8 as u64)
        }
        "SlushSize" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some((value & 0xfff) as u64)
        }
        "PoolTag" | "Key" => {
            let value: u32 = mem.read(field_addr).ok()?;
            Some(value as u64)
        }
        "Va" | "NumberOfBytes" => mem.read(field_addr).ok(),
        _ => None,
    }
}

fn buf_u32(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn buf_u64(buf: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        buf.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// `read_pool_field` against an already-read entry buffer
pub fn pool_field_from_buf(ti: &TypeInfo, buf: &[u8], field: &str) -> Option<u64> {
    let f = ti.fields.get(field)?;
    let offset = f.offset as usize;
    if let ParsedType::Bitfield { pos, len, .. } = &f.type_data {
        // the storage unit may be narrower than 8 bytes at the end of the entry
        let raw = buf_u64(buf, offset).or_else(|| buf_u32(buf, offset).map(u64::from))?;
        let mask = if *len == 64 {
            u64::MAX
        } else {
            (1u64 << *len) - 1
        };
        return Some((raw >> *pos) & mask);
    }

    match field {
        "PreviousSize" | "PoolIndex" | "BlockSize" | "PoolType" | "Pattern" => {
            Some(buf_u32(buf, offset)? as u8 as u64)
        }
        "SlushSize" => Some((buf_u32(buf, offset)? & 0xfff) as u64),
        "PoolTag" | "Key" => Some(buf_u32(buf, offset)? as u64),
        "Va" | "NumberOfBytes" => buf_u64(buf, offset),
        _ => None,
    }
}

pub fn tag_string(tag: u32) -> String {
    let mut s = String::with_capacity(4);
    for i in 0..4 {
        let c = ((tag >> (i * 8)) & 0xff) as u8;
        s.push(if (0x20..=0x7e).contains(&c) {
            c as char
        } else {
            '.'
        });
    }
    s
}

pub fn tag_looks_printable(tag: u32) -> bool {
    (0..4).all(|i| (0x20..=0x7e).contains(&((tag >> (i * 8)) & 0xff)))
}

pub fn plausible_pool_tag(tag: u32) -> bool {
    tag == POOL_FREE_TAG || tag_looks_printable(tag)
}

pub fn pool_block_state(h: &PoolHeader) -> &'static str {
    if h.synthetic_free || h.tag == POOL_FREE_TAG {
        "Free"
    } else if tag_looks_printable(h.tag) {
        "Allocated"
    } else {
        "Allocated?"
    }
}

pub fn parse_pool_header(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
) -> Option<PoolHeader> {
    let mem = debugger.current_process().ok()?.memory();
    let (previous_size, block_units, pool_type, tag) = if layout.pool_header_uses_struct {
        let previous_size =
            read_pool_field(&layout.pool_header, &mem, header, "PreviousSize")? as u8;
        let block_units = read_pool_field(&layout.pool_header, &mem, header, "BlockSize")? as u8;
        let pool_type = read_pool_field(&layout.pool_header, &mem, header, "PoolType")? as u8;
        let tag = read_pool_field(&layout.pool_header, &mem, header, "PoolTag")? as u32;
        (previous_size, block_units, pool_type, tag)
    } else {
        let word0: u32 = mem.read(header).ok()?;
        let tag: u32 = mem.read(header + layout.pool_tag_offset).ok()?;
        (
            (word0 & 0xff) as u8,
            ((word0 >> 16) & 0xff) as u8,
            ((word0 >> 24) & 0xff) as u8,
            tag,
        )
    };
    if block_units == 0 {
        return None;
    }
    Some(PoolHeader {
        header,
        body: header + layout.header_size,
        size: block_units as u64 * POOL_ALIGN,
        previous_size: previous_size as u64 * POOL_ALIGN,
        pool_type,
        tag,
        synthetic_free: false,
    })
}

pub fn pool_header_plausible(layout: &PoolLayout, h: &PoolHeader) -> bool {
    h.size >= layout.header_size
        && h.size <= POOL_PAGE_SIZE
        && (h.header.0 & !(POOL_PAGE_SIZE - 1))
            == ((h.header.0 + h.size - 1) & !(POOL_PAGE_SIZE - 1))
        && (plausible_pool_tag(h.tag) || (h.pool_type == 0 && h.previous_size == 0))
}

pub fn try_pool_header_lax(
    debugger: &Target,
    layout: &PoolLayout,
    addr: VirtAddr,
) -> Option<PoolHeader> {
    let h = parse_pool_header(debugger, layout, addr)?;
    pool_header_plausible(layout, &h).then_some(h)
}

pub fn gap_free_pool_block(
    debugger: &Target,
    layout: &PoolLayout,
    header: VirtAddr,
    size: u64,
) -> PoolHeader {
    let tag: u32 = debugger
        .current_process()
        .ok()
        .and_then(|p| p.memory().read(header + layout.pool_tag_offset).ok())
        .unwrap_or(0);
    PoolHeader {
        header,
        body: header + layout.header_size,
        size,
        previous_size: 0,
        pool_type: 0,
        tag,
        synthetic_free: true,
    }
}

pub fn walk_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut blocks = Vec::new();
    let mut addr = base;
    while addr.0 < base.0 + POOL_PAGE_SIZE {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            addr += h.size;
            blocks.push(h);
        } else {
            let mut advanced = false;
            for step in 1..=POOL_MAX_GAP_UNITS {
                let probe = addr + step * POOL_ALIGN;
                if probe.0 >= base.0 + POOL_PAGE_SIZE {
                    break;
                }
                if let Some(h2) = try_pool_header_lax(debugger, layout, probe)
                    .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
                {
                    addr = h2.header;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
    }
    blocks
}

pub fn scan_pool_page_lax(
    debugger: &Target,
    layout: &PoolLayout,
    base: VirtAddr,
) -> Vec<PoolHeader> {
    let mut candidates = Vec::new();
    let mut off = 0;
    while off < POOL_PAGE_SIZE {
        let addr = base + off;
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| h.header.0 + h.size <= base.0 + POOL_PAGE_SIZE)
        {
            candidates.push(h);
        }
        off += POOL_ALIGN;
    }
    let mut blocks = Vec::new();
    let mut cursor = base;
    for (i, h) in candidates.iter().copied().enumerate() {
        if h.header < cursor {
            continue;
        }
        if h.header == cursor
            && h.size == POOL_ALIGN
            // A minimal block with no pool type is a free-list stub, not a
            // real allocation (PoolType 0 is otherwise ordinary NonPagedPool).
            && !h.synthetic_free
            && h.tag != POOL_FREE_TAG
            && h.pool_type == 0
            && let Some(next) = candidates.get(i + 1)
            && next.header.0 > h.header.0 + POOL_ALIGN
        {
            let free_size = next.header.0 - h.header.0 - POOL_ALIGN;
            blocks.push(gap_free_pool_block(debugger, layout, h.header, free_size));
            cursor = h.header + free_size;
        } else {
            if h.header > cursor {
                let free_size = h.header.0.saturating_sub(cursor.0 + POOL_ALIGN);
                if free_size >= POOL_ALIGN * 2 {
                    blocks.push(gap_free_pool_block(debugger, layout, cursor, free_size));
                }
            }
            blocks.push(h);
            cursor = h.header + h.size;
        }
    }
    blocks
}

pub fn find_pool_block_index(blocks: &[PoolHeader], needle: &PoolHeader) -> Option<usize> {
    blocks
        .iter()
        .position(|h| h.header == needle.header && h.size == needle.size)
}

pub fn locate_pool_block_in_page(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> (Vec<PoolHeader>, Option<usize>, VirtAddr) {
    let base = VirtAddr(target.0 & !(POOL_PAGE_SIZE - 1));
    let aligned = VirtAddr(target.0 & !(POOL_ALIGN - 1));
    let mut anchor = None;
    let mut addr = aligned;
    loop {
        if let Some(h) = try_pool_header_lax(debugger, layout, addr)
            .filter(|h| target >= h.header && target.0 < h.header.0 + h.size)
        {
            anchor = Some(h);
            break;
        }
        if addr <= base {
            break;
        }
        addr -= POOL_ALIGN;
    }
    let Some(anchor) = anchor else {
        return (Vec::new(), None, base);
    };
    let blocks = walk_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    let blocks = scan_pool_page_lax(debugger, layout, base);
    if let Some(idx) = find_pool_block_index(&blocks, &anchor) {
        return (blocks, Some(idx), base);
    }
    (vec![anchor], Some(0), base)
}

pub fn classify_pool_region(
    debugger: &Target,
    addr: VirtAddr,
) -> Option<(&'static str, VirtAddr, VirtAddr)> {
    let dtb = debugger.current_dtb();
    let mem = debugger.current_process().ok()?.memory();
    let bound = |symbol: &str| {
        let address = debugger
            .symbols
            .find_symbol_across_modules(dtb, &format!("nt!{symbol}"))
            .ok()
            .flatten()?;
        mem.read::<u64>(address).ok().map(VirtAddr)
    };
    for (name, start, stop) in [
        ("NonPagedPool", "MmNonPagedPoolStart", "MmNonPagedPoolEnd"),
        ("PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd"),
        ("SpecialPool", "MmSpecialPoolStart", "MmSpecialPoolEnd"),
    ] {
        // A range whose symbols this build lacks says nothing about the
        // others; keep looking.
        let (Some(s), Some(e)) = (bound(start), bound(stop)) else {
            continue;
        };
        if (s..e).contains(&addr) {
            return Some((name, s, e));
        }
    }
    None
}

pub fn parse_big_pool_entry(
    layout: &PoolLayout,
    entry: VirtAddr,
    buf: &[u8],
) -> Option<BigPoolEntry> {
    let ti = layout.big_pool_type.as_ref()?;
    let (va_raw, size, tag, pattern, pool_flags, slush_size) = if layout.big_pool_uses_struct {
        let va_raw = pool_field_from_buf(ti, buf, "Va")?;
        let size = pool_field_from_buf(ti, buf, "NumberOfBytes")?;
        let tag = pool_field_from_buf(ti, buf, "Key")? as u32;
        let pattern = pool_field_from_buf(ti, buf, "Pattern")? as u8;
        let pool_flags = if layout.big_pool_has_pool_type {
            pool_field_from_buf(ti, buf, "PoolType").unwrap_or(0) as u16 & 0xfff
        } else {
            0
        };
        let slush_size = if layout.big_pool_has_slush {
            pool_field_from_buf(ti, buf, "SlushSize").unwrap_or(0) as u16 & 0xfff
        } else {
            0
        };
        (va_raw, size, tag, pattern, pool_flags, slush_size)
    } else {
        let va_raw = buf_u64(buf, ti.field_offset("Va").ok()? as usize)?;
        let size = buf_u64(buf, ti.field_offset("NumberOfBytes").ok()? as usize)?;
        let tag = buf_u32(buf, ti.field_offset("Key").ok()? as usize)?;
        let flags_word = buf_u32(buf, ti.field_offset("Pattern").ok()? as usize)?;
        (
            va_raw,
            size,
            tag,
            (flags_word & 0xff) as u8,
            ((flags_word >> 8) & 0xfff) as u16,
            ((flags_word >> 20) & 0xfff) as u16,
        )
    };
    let va = VirtAddr(va_raw & !1);
    if va.is_zero() || size == 0 || !plausible_pool_tag(tag) {
        return None;
    }
    Some(BigPoolEntry {
        va,
        entry,
        index: 0,
        nonpaged: va_raw & 1 != 0,
        size,
        tag,
        pattern,
        pool_flags,
        slush_size,
    })
}

pub fn find_big_pool(
    debugger: &Target,
    layout: &PoolLayout,
    target: VirtAddr,
) -> Option<BigPoolEntry> {
    let table_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "nt!PoolBigPageTable")
        .ok()
        .flatten()?;
    let mem = debugger.current_process().ok()?.memory();
    let table_addr = VirtAddr(mem.read::<u64>(table_sym).ok()?);
    let count_sym = debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "nt!PoolBigPageTableSize")
        .ok()
        .flatten()?;
    let count: u64 = mem.read(count_sym).ok()?;
    if count == 0 || count > 0x100000 {
        return None;
    }
    let entry_size = layout.big_pool_entry_size.filter(|s| *s > 0)?;
    // Scan the table in bulk reads; per-field reads would cost a page-table
    // walk and a syscall per field, times up to 0x100000 entries
    const CHUNK_ENTRIES: u64 = 1024;
    let mut chunk = vec![0u8; (CHUNK_ENTRIES * entry_size) as usize];
    let mut i = 0;
    while i < count {
        let n = CHUNK_ENTRIES.min(count - i);
        let chunk_addr = table_addr + i * entry_size;
        let chunk = &mut chunk[..(n * entry_size) as usize];
        if mem.read_bytes(chunk_addr, chunk).is_err() {
            // Retry per entry so one unreadable page doesn't hide the rest;
            // entries left zeroed parse to None and are skipped
            chunk.fill(0);
            for j in 0..n {
                let buf = &mut chunk[(j * entry_size) as usize..((j + 1) * entry_size) as usize];
                let _ = mem.read_bytes(chunk_addr + j * entry_size, buf);
            }
        }
        for j in 0..n {
            let buf = &chunk[(j * entry_size) as usize..((j + 1) * entry_size) as usize];
            let entry_addr = chunk_addr + j * entry_size;
            if let Some(mut entry) = parse_big_pool_entry(layout, entry_addr, buf)
                .filter(|e| target >= e.va && target.0 < e.va.0 + e.size)
            {
                entry.index = i + j;
                return Some(entry);
            }
        }
        i += n;
    }
    None
}

pub fn segment_heap_hint(debugger: &Target) -> Option<&'static str> {
    debugger
        .symbols
        .find_symbol_across_modules(debugger.current_dtb(), "nt!RtlpHpHeapGlobals")
        .ok()
        .flatten()?;
    Some(
        "kernel has RtlpHpHeapGlobals (segment heap is enabled); address may be a _HEAP_VS_CHUNK_HEADER / LFH chunk instead of a _POOL_HEADER",
    )
}

pub fn annotate_near_symbol(debugger: &Target, addr: VirtAddr) -> Option<String> {
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.current_dtb(), addr)?;
    (offset <= 0x1000).then(|| format_symbol_with_offset(&module, &name, offset))
}

pub fn print_pool_page_listing(blocks: &[PoolHeader], target_idx: Option<usize>, target: VirtAddr) {
    if blocks.is_empty() {
        outln!("  (no plausible pool block found for this address)");
        return;
    }
    outln!(
        "    {:<16} {:<8} {:<8} {:<12} {:<6} tag",
        "header",
        "size",
        "prev",
        "state",
        "type"
    );
    for (i, h) in blocks.iter().enumerate() {
        let marker = if Some(i) == target_idx {
            ">".yellow().to_string()
        } else {
            " ".to_string()
        };
        outln!(
            "  {} {} 0x{:<6x} 0x{:<6x} {:<12} 0x{:<4x} '{}'",
            marker,
            ui::addr(h.header.0),
            h.size,
            h.previous_size,
            pool_block_state(h),
            h.pool_type,
            tag_string(h.tag)
        );
    }
    if let Some(idx) = target_idx {
        let h = &blocks[idx];
        let offset = target.0.saturating_sub(h.body.0);
        outln!(
            "  target offset : 0x{:x} into body (block @ {}, body @ {})",
            offset,
            ui::addr(h.header.0),
            ui::addr(h.body.0)
        );
    }
}

pub fn print_big_pool(target: VirtAddr, entry: &BigPoolEntry) {
    let offset = target.0 - entry.va.0;
    let end_addr = entry.va + entry.size;
    outln!("big pool @ {}", ui::addr(entry.va.0));
    outln!("  target        : {}", ui::addr(target.0));
    outln!(
        "  range         : {} - {} ({} bytes)",
        ui::addr(entry.va.0),
        ui::addr(end_addr.0),
        entry.size
    );
    outln!("  offset        : 0x{:x} / 0x{:x}", offset, entry.size);
    outln!(
        "  tag           : '{}' (0x{:08x})",
        tag_string(entry.tag),
        entry.tag
    );
    outln!(
        "  table entry   : {}[{}]",
        ui::addr(entry.entry.0),
        entry.index
    );
    outln!(
        "  nonpaged      : {}",
        if entry.nonpaged { "yes" } else { "no" }
    );
    outln!("  pattern       : 0x{:x}", entry.pattern);
    outln!("  pool flags    : 0x{:x}", entry.pool_flags);
    outln!("  slush size    : 0x{:x}", entry.slush_size);
}
