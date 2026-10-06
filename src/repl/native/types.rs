//! `dt` as a card: the type in the head, its fields as a tree under it
//! (nested structures and arrays folded), or the records of a `-l` walk;
//! an enum as a table of its values.

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Node, Span, TableRow, TextAlign, TreeItem, Truncate, Wrap};

use super::{MUTED, NUMBER, STRONG, TYPE, addr, span};
use crate::repl::commands::types::{DtBody, DtDump, DtEntry, DtField};

pub fn view(dump: &DtDump) -> View {
    let mut head = vec![
        span(dump.type_name.as_str(), TYPE),
        span(format!(" ({} bytes)", dump.size), MUTED),
    ];
    if let Some(address) = dump.address {
        head.push(span(" @ ", MUTED));
        head.push(addr(address));
    }
    let mut card = ui::card().head(head).role("ntoseye.dt");
    match &dump.body {
        DtBody::Fields(entries) => {
            if !entries.is_empty() {
                // One field path asked for by name opens; anything else
                // starts with only the top level showing.
                let open = entries.len() == 1;
                card = card.child(tree(entries, "f", open));
            }
        }
        DtBody::List { records, stop } => {
            let mut records_tree = ui::tree();
            for (index, (record, entries)) in records.iter().enumerate() {
                let id = format!("r{index}");
                let mut item = TreeItem::new(
                    id.as_str(),
                    vec![
                        span(dump.type_name.as_str(), TYPE),
                        span(" @ ", MUTED),
                        addr(*record),
                    ],
                )
                .open(true);
                for (child, entry) in entries.iter().enumerate() {
                    item = item.child(entry_item(entry, format!("{id}.{child}"), false));
                }
                records_tree = records_tree.item(item);
            }
            card = card.child(records_tree);
            if let Some(stop) = stop {
                card = card.child(ui::text([span(stop.as_str(), "warning")]).wrap(Wrap::Word));
            }
        }
        DtBody::Failed(message) => {
            card = card.child(ui::text([span(message.as_str(), "error")]).wrap(Wrap::Word));
        }
    }
    View::new().main([card])
}

/// `entries` as a tree, ids under `prefix`.
fn tree(entries: &[DtEntry], prefix: &str, open: bool) -> Node {
    let mut tree = ui::tree();
    for (index, entry) in entries.iter().enumerate() {
        tree = tree.item(entry_item(entry, format!("{prefix}{index}"), open));
    }
    tree.into()
}

fn entry_item(entry: &DtEntry, id: String, open: bool) -> TreeItem {
    match entry {
        DtEntry::Field(field) => {
            let mut item = TreeItem::new(id.as_str(), field_label(field));
            if !field.children.is_empty() {
                item = item.open(open);
            }
            for (index, child) in field.children.iter().enumerate() {
                item = item.child(entry_item(child, format!("{id}.{index}"), false));
            }
            item
        }
        DtEntry::Note(note) => TreeItem::new(id, vec![span(note.as_str(), MUTED)]),
        DtEntry::Error(message) => TreeItem::new(id, vec![span(message.as_str(), "error")]),
    }
}

/// `+0x018 Flags : Uint4B = 0x8000000`: the offset quiet, the name strong,
/// the type a type, a number a number.
fn field_label(field: &DtField) -> Vec<Span> {
    let mut label = Vec::with_capacity(7);
    match field.offset {
        Some(offset) => {
            label.push(span(format!("+0x{offset:03x} "), MUTED));
            label.push(span(field.name.as_str(), STRONG));
        }
        None => label.push(span(field.name.as_str(), MUTED)),
    }
    label.push(span(" : ", MUTED));
    label.push(span(field.type_name.as_str(), TYPE));
    if let Some(size) = field.size {
        label.push(span(format!(" [size {size}]"), MUTED));
    }
    if let Some(value) = &field.value {
        label.push(span(" = ", MUTED));
        let style = if value.starts_with("<unavailable") {
            MUTED
        } else if field.numeric {
            NUMBER
        } else {
            ""
        };
        label.push(span(value.as_str(), style));
    }
    label
}

/// `dt` of an enum: its values and names.
pub fn enum_view(name: &str, variants: &[(String, i64)]) -> View {
    let head = vec![
        span("enum ", MUTED),
        span(name, TYPE),
        span(format!(" ({} values)", variants.len()), MUTED),
    ];
    let mut table = ui::table()
        .col(
            Column::new("value", "Value")
                .align(TextAlign::End)
                .priority(2.0),
        )
        .col(
            Column::new("name", "Name")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(3.0),
        );
    for (index, (variant, value)) in variants.iter().enumerate() {
        table = table.row(
            TableRow::new(index.to_string())
                .cell("value", vec![span(format!("{value:#x}"), NUMBER)])
                .cell("name", vec![span(variant.as_str(), STRONG)]),
        );
    }
    let card = ui::card().head(head).role("ntoseye.dt").child(table);
    View::new().main([card])
}
