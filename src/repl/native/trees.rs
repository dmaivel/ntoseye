//! Hierarchies as Tern trees: the `wt` call tree and the hypervisor's
//! partitions with their VPs.

use tern_sdk::View;
use tern_sdk::ui::{self, Span, TreeItem};

use super::{MUTED, NUMBER, STRONG, addr, span, symbol};
use crate::guest::privilege_names;
use crate::repl::commands::vtl::{PartitionNode, VpNode, other_vtls, processors_text, vp_state};
use crate::session::CallTraceFrame;

/// How many levels of the call tree start open: the traced function and
/// the calls it made.
const OPEN_CALL_LEVELS: usize = 2;

/// The `wt` call tree: each function with the instructions it ran itself,
/// its calls nested below it.
pub fn call_tree(root: &CallTraceFrame) -> View {
    View::new().main([ui::tree().item(call_item(root, "0".to_string(), 0))])
}

fn call_item(frame: &CallTraceFrame, id: String, depth: usize) -> TreeItem {
    let mut label = symbol(&frame.name);
    label.push(span("  ", ""));
    label.push(span(frame.instructions.to_string(), NUMBER));
    label.push(span(" instructions", MUTED));
    let mut item = TreeItem::new(id.as_str(), label).open(depth < OPEN_CALL_LEVELS);
    for (index, child) in frame.children.iter().enumerate() {
        item = item.child(call_item(child, format!("{id}.{index}"), depth + 1));
    }
    item
}

/// The partitions, each under its parent, with their privileges (folded)
/// and VPs.
pub fn partitions(forest: &[PartitionNode<'_>]) -> View {
    let mut tree = ui::tree();
    for node in forest {
        tree = tree.item(partition_item(node));
    }
    View::new().main([tree])
}

fn partition_item(node: &PartitionNode<'_>) -> TreeItem {
    let partition = node.partition;
    let id = format!("p{:x}", partition.id);
    let mut label = vec![span(format!("partition {:#x}", partition.id), STRONG)];
    if partition.parent.is_none() {
        label.push(span("  root", "info"));
    }
    label.push(span(format!("  {:016x}", partition.address), MUTED));
    let mut item = TreeItem::new(id.as_str(), label).open(true);

    let (names, unnamed) = privilege_names(partition.privileges);
    let mut privileges = TreeItem::new(
        format!("{id}.priv"),
        vec![
            span("privileges ", MUTED),
            span(format!("{:016x}", partition.privileges), NUMBER),
        ],
    );
    for name in names {
        privileges = privileges.child(TreeItem::new(
            format!("{id}.priv.{name}"),
            vec![span(name, MUTED)],
        ));
    }
    if unnamed != 0 {
        privileges = privileges.child(TreeItem::new(
            format!("{id}.priv.unnamed"),
            vec![span(format!("+{unnamed:#x}"), MUTED)],
        ));
    }
    item = item.child(privileges);

    for vp in &node.vps {
        item = item.child(TreeItem::new(
            format!("{id}.vp{}", vp.vp.index),
            vp_label(vp),
        ));
    }
    for child in &node.children {
        item = item.child(partition_item(child));
    }
    item
}

/// `VP 0  CPU 0  VTL0 (+VTL1)  nt!HalProcessorIdle+0x1d  last exit HLT`,
/// the processor and the other VTLs quiet.
fn vp_label(node: &VpNode<'_>) -> Vec<Span> {
    let vp = node.vp;
    let mut label = vec![span(format!("VP {}", vp.index), STRONG)];
    let cpu = processors_text(&vp.processors);
    if !cpu.is_empty() {
        label.push(span(format!("  CPU {cpu}"), MUTED));
    }
    label.push(span(format!("  VTL{}", vp.vtl), ""));
    let others = other_vtls(vp);
    if !others.is_empty() {
        label.push(span(others, MUTED));
    }
    let Some(state) = vp_state(vp) else {
        return label;
    };
    label.push(span("  ", ""));
    match &node.symbol {
        Some(name) => label.extend(symbol(name)),
        None => label.push(addr(state.rip)),
    }
    if let Some(exit) = state.exit_reason_name() {
        label.push(span(format!("  last exit {exit}"), MUTED));
    }
    label
}
