//! `.frame`, `!pte`, `!pool` and `vars` as Tern views.

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Node, Span, TableRow, TextAlign, Truncate};

use super::{MUTED, NUMBER, STRONG, addr, block, span, styled, symbol};
use crate::repl::commands::frames::FrameLine;
use crate::repl::print_sparse_registers;
use crate::target::mm::{PoolBlockDetail, PoolPageDetail, PteLevel, PteWalk};
use crate::target::{BuiltinVar, SelectedFrame, UserVar};
use crate::types::{PageTableLevel, VirtAddr};

/// The marker `native::stack::numbered` puts before the selected row.
const PICK: &str = "\u{25b8} ";

/// `.frame`: the selected frame as a one-row stack table, marked, then its
/// frame base and (with `/r`) its recovered registers.
pub fn frame(line: &FrameLine, frame: &SelectedFrame, show_registers: bool) -> View {
    let table = ui::table()
        .col(Column::new("n", "#").align(TextAlign::End).priority(4.0))
        .col(Column::new("sp", "Child-SP").priority(2.0))
        .col(Column::new("ip", "Address").priority(3.0))
        .col(
            Column::new("site", "Call site")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(5.0),
        );
    let mut site = symbol(&line.symbol);
    if line.inline {
        site.push(span("  [inline]", MUTED));
    }
    if let Some(location) = &line.location {
        site.push(span(format!("  [{location}]"), MUTED));
    }
    let table = table.row(
        TableRow::new(frame.index.to_string())
            .cell("n", span(format!("{PICK}{:02}", frame.index), STRONG))
            .cell("sp", span(format!("{:016x}", frame.sp), MUTED))
            .cell("ip", span(format!("{:016x}", frame.ip), STRONG))
            .cell("site", site),
    );
    let mut nodes = vec![Node::from(table)];
    if let Some(base) = frame.frame_base {
        nodes.push(Node::from(ui::kv().item("frame base", addr(base))));
    }
    if show_registers {
        let registers = styled(|| print_sparse_registers(&frame.registers, None, 0));
        nodes.push(Node::from(
            ui::section()
                .head("registers")
                .collapsible(true)
                .collapsed(false)
                .child(block(&registers)),
        ));
    }
    View::new().main(nodes)
}

/// `!pte`: the VA and address space, then one row per level reached, and
/// the physical address the walk resolves to when it reaches a present leaf.
pub fn pte(walk: &PteWalk, invalid_pte_mask: u64) -> View {
    let mut table = ui::table()
        .col(Column::new("level", "Level").priority(5.0))
        .col(Column::new("entry", "Entry").priority(2.0))
        .col(Column::new("contents", "Contents").priority(4.0))
        .col(
            Column::new("pfn", "PFN")
                .align(TextAlign::End)
                .priority(3.0),
        )
        .col(Column::new("flags", "Flags").grow(1.0).priority(1.0));
    for level in walk.levels() {
        table = table.row(pte_row(level, invalid_pte_mask));
    }

    let mut details = ui::kv()
        .item("VA", addr(walk.address.0))
        .item("DTB", addr(walk.dtb));
    let leaf = walk.levels().last().filter(|level| {
        level.attributes.present
            && (level.level == PageTableLevel::Pte || level.attributes.large_page)
    });
    if let Some(leaf) = leaf {
        let page_size: u64 = match leaf.level {
            PageTableLevel::Pte | PageTableLevel::Pxe => 0x1000,
            PageTableLevel::Pde => 0x20_0000,
            PageTableLevel::Ppe => 0x4000_0000,
        };
        let physical =
            (leaf.attributes.pfn << 12 & !(page_size - 1)) | (walk.address.0 & (page_size - 1));
        let mut value = vec![addr(physical)];
        if leaf.attributes.large_page {
            value.push(span(format!("  large page ({})", leaf.level.name()), MUTED));
        }
        details = details.item("physical", value);
    }
    View::new().main([Node::from(details), Node::from(table)])
}

fn pte_row(level: &PteLevel, invalid_pte_mask: u64) -> TableRow {
    let attributes = &level.attributes;
    let value = level.value;
    let (pfn, flags) = if attributes.present {
        (
            span(format!("{:x}", attributes.pfn), NUMBER),
            pte_flags(&attributes.flags),
        )
    } else if value.is_transition() {
        (
            span(
                format!("{:x}", value.unswizzled(invalid_pte_mask).pfn()),
                NUMBER,
            ),
            vec![span("transition", "warning")],
        )
    } else {
        (span("-", MUTED), vec![span("not present", MUTED)])
    };
    TableRow::new(level.level.name())
        .cell("level", span(level.level.name(), STRONG))
        .cell("entry", span(format!("{:016x}", level.address.0), MUTED))
        .cell("contents", addr(value.0))
        .cell("pfn", pfn)
        .cell("flags", flags)
}

/// The text's flag string, each letter colored: valid as success, write
/// as warning, the rest and the `-` placeholders quiet.
fn pte_flags(flags: &str) -> Vec<Span> {
    flags
        .chars()
        .map(|flag| {
            let style = match flag {
                'V' => "success",
                'W' => "warning",
                '-' => "dim",
                _ => MUTED,
            };
            span(flag.to_string(), style)
        })
        .collect()
}

/// `!pool`: the big-pool allocation as key/value pairs, or the pool page's
/// facts over its blocks, the one holding the address marked.
pub fn pool(detail: &PoolPageDetail, target: VirtAddr) -> View {
    if let Some(big) = &detail.big {
        let kv = ui::kv()
            .item("big pool", addr(big.address.0))
            .item("target", addr(big.target.0))
            .item(
                "range",
                [
                    addr(big.address.0),
                    span(" - ", MUTED),
                    addr(big.address.0.saturating_add(big.size)),
                    span(format!("  {} bytes", big.size), MUTED),
                ],
            )
            .item(
                "offset",
                [
                    span(format!("0x{:x}", big.offset), NUMBER),
                    span(format!(" / 0x{:x}", big.size), MUTED),
                ],
            )
            .item(
                "tag",
                [
                    span(format!("'{}'", big.tag_name), STRONG),
                    span(format!("  0x{:08x}", big.tag), MUTED),
                ],
            )
            .item(
                "table entry",
                [addr(big.entry.0), span(format!("[{}]", big.index), MUTED)],
            )
            .item(
                "nonpaged",
                span(if big.nonpaged { "yes" } else { "no" }, ""),
            )
            .item("pattern", span(format!("0x{:x}", big.pattern), NUMBER))
            .item(
                "pool flags",
                span(format!("0x{:x}", big.pool_flags), NUMBER),
            )
            .item(
                "slush size",
                span(format!("0x{:x}", big.slush_size), NUMBER),
            );
        return View::new().main([kv]);
    }

    let mut kv = ui::kv()
        .item("pool page", addr(detail.page.0))
        .item("target", addr(target.0));
    if let Some(region) = &detail.region {
        kv = kv.item(
            "region",
            [
                span(&region.name, STRONG),
                span("  ", ""),
                addr(region.start.0),
                span(" - ", MUTED),
                addr(region.end.0),
            ],
        );
    }
    if let Some(idx) = detail.target_index {
        kv = kv.item(
            "blocks in run",
            [
                span(detail.blocks.len().to_string(), NUMBER),
                span(format!("  target is #{}", idx + 1), MUTED),
            ],
        );
        if let Some(offset) = detail.blocks[idx].target_offset {
            let block = &detail.blocks[idx];
            kv = kv.item(
                "target offset",
                [
                    span(format!("0x{offset:x}"), NUMBER),
                    span(" into body  block ", MUTED),
                    addr(block.header.0),
                    span("  body ", MUTED),
                    addr(block.body.0),
                ],
            );
        }
    }
    if let Some(hint) = &detail.segment_heap_hint {
        kv = kv.item("hint", span(hint, ""));
    }
    if let Some(near) = &detail.near_symbol {
        kv = kv.item("near symbol", symbol(near));
    }
    let mut nodes = vec![Node::from(kv)];

    if detail.blocks.is_empty() {
        nodes.push(Node::from(ui::text([span(
            "no plausible pool block found for this address",
            MUTED,
        )])));
    } else {
        let mut table = ui::table()
            .col(Column::new("header", "Header").priority(5.0))
            .col(
                Column::new("size", "Size")
                    .align(TextAlign::End)
                    .priority(4.0),
            )
            .col(
                Column::new("prev", "Prev")
                    .align(TextAlign::End)
                    .priority(1.0),
            )
            .col(Column::new("state", "State").priority(3.0))
            .col(
                Column::new("type", "Type")
                    .align(TextAlign::End)
                    .priority(2.0),
            )
            .col(Column::new("tag", "Tag").grow(1.0).priority(6.0));
        for block in &detail.blocks {
            table = table.row(pool_row(block));
        }
        nodes.push(Node::from(table));
    }

    if let Some(message) = &detail.message {
        nodes.push(Node::from(ui::text([span(
            format!(
                "{message}. it may be segment heap, special pool, a mapped view, or image/stack."
            ),
            "warning",
        )])));
    }
    View::new().main(nodes)
}

fn pool_row(block: &PoolBlockDetail) -> TableRow {
    let header = if block.marked {
        span(format!("{PICK}{:016x}", block.header.0), STRONG)
    } else {
        addr(block.header.0)
    };
    let strong = |text: String, style: &str| {
        if block.marked {
            span(text, &format!("{style} {STRONG}"))
        } else {
            span(text, style)
        }
    };
    TableRow::new(format!("{:x}", block.header.0))
        .cell("header", header)
        .cell("size", strong(format!("0x{:x}", block.size), NUMBER))
        .cell("prev", span(format!("0x{:x}", block.previous_size), MUTED))
        .cell(
            "state",
            strong(
                block.state.clone(),
                if block.allocated { "success" } else { MUTED },
            ),
        )
        .cell("type", span(format!("0x{:x}", block.pool_type), MUTED))
        .cell("tag", strong(format!("'{}'", block.tag_name), STRONG))
}

/// `vars`: user variables, the result slots, and the builtins, each a
/// section holding a name/value/source table.
pub fn vars(
    user: &[(&str, &UserVar)],
    results: usize,
    origin: Option<&str>,
    builtins: &[BuiltinVar],
) -> View {
    let mut nodes = Vec::new();
    if !user.is_empty() {
        let rows = user
            .iter()
            .map(|(name, var)| var_row(name, var.value, &var.source, STRONG));
        nodes.push(var_section("user", rows));
    }
    if results != 0 {
        let mut text = vec![span(format!("$0..${}", results - 1), "info")];
        if let Some(origin) = origin {
            text.push(span(format!("   from: {origin}"), MUTED));
        }
        nodes.push(Node::from(
            ui::section()
                .head("results")
                .collapsible(true)
                .collapsed(false)
                .child(ui::text(text)),
        ));
    }
    if !builtins.is_empty() {
        let rows = builtins
            .iter()
            .map(|var| var_row(var.name, var.value, var.source, "info"));
        nodes.push(var_section("builtins", rows));
    }
    View::new().main(nodes)
}

fn var_section(title: &str, rows: impl Iterator<Item = TableRow>) -> Node {
    let mut table = ui::table()
        .col(Column::new("name", "Name").priority(3.0))
        .col(Column::new("value", "Value").priority(2.0))
        .col(
            Column::new("source", "Source")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(1.0),
        );
    for row in rows {
        table = table.row(row);
    }
    Node::from(
        ui::section()
            .head(title)
            .collapsible(true)
            .collapsed(false)
            .child(table),
    )
}

fn var_row(name: &str, value: u64, source: &str, style: &str) -> TableRow {
    TableRow::new(name)
        .cell("name", span(format!("${name}"), style))
        .cell("value", addr(value))
        .cell("source", span(source, MUTED))
}
