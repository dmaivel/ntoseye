//! The `.help` listing: one open section per category, each a header-less
//! table of names and what they do.

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Node, TableRow, Truncate};

use super::{MUTED, STRONG, span};
use crate::repl::CommandSpec;
use crate::repl::commands::meta::HelpGroup;

pub fn view(groups: &[HelpGroup]) -> View {
    let sections = groups.iter().map(|group| {
        let mut table = ui::table()
            .col(
                Column {
                    id: "name".into(),
                    ..Column::default()
                }
                .priority(2.0),
            )
            .col(
                Column {
                    id: "summary".into(),
                    ..Column::default()
                }
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(1.0),
            );
        for entry in &group.entries {
            let mut summary = vec![span(entry.summary.as_str(), "")];
            if !entry.aliases.is_empty() {
                summary.push(span(format!("  aliases: {}", entry.aliases), MUTED));
            }
            table = table.row(
                TableRow::new(entry.name.as_str())
                    .cell("name", vec![span(entry.name.as_str(), STRONG)])
                    .cell("summary", summary),
            );
        }
        Node::from(
            ui::section()
                .head(group.title.as_str())
                .collapsible(true)
                .collapsed(false)
                .child(table),
        )
    });
    View::new().main(sections.collect::<Vec<Node>>())
}

/// `.help <command>`: the command and its other names, what it does, its
/// usage, and the details as Markdown, so their `code` reads as code.
pub fn command(spec: &CommandSpec) -> View {
    let mut head = vec![span(spec.names[0], STRONG)];
    if spec.names.len() > 1 {
        head.push(span(format!("  {}", spec.names[1..].join(", ")), MUTED));
    }
    let mut card = ui::card()
        .head(head)
        .role("ntoseye.help")
        .child(ui::md(spec.summary))
        .child(ui::code(spec.usage));
    if let Some(details) = spec.details {
        card = card.child(ui::md(details));
    }
    View::new().main([card])
}
