use ntoseye_macros::command;

use crate::error::Result;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::pnp::{
    DevNodeDetail, DevNodeSummary, DeviceStackDetail, PnpTriageDetail, StateHistoryEntry,
};
use crate::types::VirtAddr;
use crate::ui;

const HISTORY_DISPLAY_LIMIT: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevNodeRequest {
    node: Option<String>,
    recursive: bool,
}

fn parse_devnode_request<'a>(argv: impl IntoIterator<Item = &'a str>) -> Option<DevNodeRequest> {
    let mut node = None;
    let mut root = false;
    let mut recursive = false;

    for argument in argv {
        match argument {
            "-r" | "1" => {
                if recursive {
                    return None;
                }
                recursive = true;
            }
            "0" => {
                if node.is_some() || root {
                    return None;
                }
                root = true;
            }
            value if value.starts_with('-') => return None,
            value if node.is_none() => node = Some(value.to_string()),
            _ => return None,
        }
    }

    Some(DevNodeRequest { node, recursive })
}

fn state_text(code: u32, name: &str) -> String {
    if name == format!("{code:#x}") {
        name.to_string()
    } else {
        format!("{name} ({code:#x})")
    }
}

fn problem_text(code: u32, name: Option<&str>) -> String {
    name.map_or_else(|| format!("{code:#x}"), str::to_string)
}

fn compact_devnode_line(node: &DevNodeSummary) -> String {
    let mut line = format!(
        "DevNode {}  PDO {}  {}  [{}]  {}",
        ui::addr(node.address.0),
        ui::addr(node.pdo.0),
        node.instance_path,
        node.service_name,
        node.state_name
    );
    if node.problem != 0 {
        line.push_str(&format!(
            "  problem={} status={:#x}",
            problem_text(node.problem, node.problem_name.as_deref()),
            node.problem_status
        ));
    }
    line
}

fn history_tail(history: &[StateHistoryEntry]) -> &[StateHistoryEntry] {
    let first = history.len().saturating_sub(HISTORY_DISPLAY_LIMIT);
    &history[first..]
}

fn print_devnode(node: &DevNodeDetail) {
    outln!(
        "DevNode {} for PDO {}",
        ui::addr(node.address.0),
        ui::addr(node.pdo.0)
    );
    outln!(
        "  Parent {} Sibling {} Child {}",
        ui::addr(node.parent.0),
        ui::addr(node.sibling.0),
        ui::addr(node.child.0)
    );
    outln!("  InstancePath is \"{}\"", node.instance_path);
    outln!("  ServiceName is \"{}\"", node.service_name);
    outln!("  State = {}", state_text(node.state, &node.state_name));
    outln!(
        "  Previous State = {}",
        state_text(node.previous_state, &node.previous_state_name)
    );
    for entry in history_tail(&node.state_history) {
        outln!(
            "  StateHistory[{}] = {}",
            entry.index,
            state_text(entry.state, &entry.state_name)
        );
    }
    outln!(
        "  Flags {:#x}  UserFlags {:#x}",
        node.flags,
        node.user_flags
    );
    if node.completion_status != 0 {
        outln!("  CompletionStatus {:#x}", node.completion_status);
    }
    if node.problem != 0 {
        outln!(
            "  Problem = {} ({})  status {:#x}",
            problem_text(node.problem, node.problem_name.as_deref()),
            node.problem,
            node.problem_status
        );
    }
    if !node.pending_irp.is_zero() {
        outln!("  PendingIrp {}", ui::addr(node.pending_irp.0));
    }
}

fn print_devnode_summary(node: &DevNodeSummary) {
    outln!("!DevNode {} :", ui::addr(node.address.0));
    outln!("  DeviceInst is \"{}\"", node.instance_path);
    outln!("  ServiceName is \"{}\"", node.service_name);
    outln!("  State = {}", state_text(node.state, &node.state_name));
}

fn print_devnode_tree(nodes: &[DevNodeSummary], truncated: bool) {
    let top = nodes.first().map_or(0, |node| node.depth);
    for node in nodes {
        let indentation = "  ".repeat((node.depth.saturating_sub(top) as usize).min(64));
        outln!("{}{}", indentation, compact_devnode_line(node));
    }
    if truncated {
        outln!("  ... devnode walk bound reached");
    }
}

fn print_device_stack(stack: &DeviceStackDetail) {
    outln!(
        "  {:<18} {:<18} {:<18}{}",
        "!DevObj",
        "!DrvObj",
        "!DevExt",
        "ObjectName"
    );
    for entry in &stack.entries {
        let marker = if entry.is_argument { ">" } else { " " };
        outln!(
            "{} {:<18} {:<18} {:<18}{}",
            marker,
            ui::addr(entry.device_object.0),
            entry.driver_name,
            ui::addr(entry.device_extension.0),
            entry.object_name
        );
    }
    if stack.truncated {
        outln!("  ... device stack bound reached");
    }
    if let Some(error) = &stack.pdo_devnode_error {
        error!("{error}");
    } else {
        match &stack.pdo_devnode {
            Some(node) => print_devnode_summary(node),
            None => outln!("!DevNode {}", ui::addr(0)),
        }
    }
}

fn print_pnp_triage(triage: &PnpTriageDetail) {
    outln!("Problem devnodes:");
    if triage.problems.is_empty() {
        outln!("  none");
    } else {
        for node in &triage.problems {
            outln!("  {}", compact_devnode_line(node));
        }
    }

    outln!("Devnodes not started:");
    if triage.not_started.is_empty() {
        outln!("  none");
    } else {
        for node in &triage.not_started {
            outln!("  {}", compact_devnode_line(node));
        }
    }

    outln!("Devnodes with pending PnP IRPs:");
    if triage.pending_irps.is_empty() {
        outln!("  none");
    } else {
        for node in &triage.pending_irps {
            outln!(
                "  {}  pending={}",
                compact_devnode_line(node),
                ui::addr(node.pending_irp.0)
            );
        }
    }

    outln!(
        "{} devnode(s): {} started, {} with problems, {} not started, {} with pending IRPs{}",
        triage.total,
        triage.started,
        triage.problems.len(),
        triage.not_started.len(),
        triage.pending_irps.len(),
        if triage.truncated {
            " (walk bound reached)"
        } else {
            ""
        }
    );
}

/// `!devnode`'s node: the line is checked whole first (`[node|0] [-r|1]`,
/// in any order), then the node's word, if any, is taken.
fn devnode_node(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    let request = parse_devnode_request(cursor.words()).ok_or(ArgError::Missing)?;
    let words: Vec<String> = cursor.words().map(str::to_string).collect();
    // Take every word but the recursion flag, which `devnode_recurse` takes.
    let mut kept = 0;
    for word in &words {
        if word == "-r" || word == "1" {
            kept += 1;
        } else {
            cursor.word_at(kept);
        }
    }
    request.node.map(|text| cx.eval(&text)).transpose()
}

/// `!devnode`'s `-r` (or WinDbg's trailing `1`), left by `devnode_node`.
fn devnode_recurse(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<bool>, ArgError> {
    Ok(cursor.word().map(|_| true))
}

/// Show a PnP device node and, optionally, its subtree.
///
/// Shows the instance path, the service, the state and state history, the
/// flags, the problem code, and the pending IRP of a device node. If you do not
/// give a node, or give 0, the command shows the root device node. Use -r, or a
/// trailing 1 as in WinDbg, to walk the subtree of the node, with one node on
/// each line.
#[command(
    names = ["!devnode", "devnode"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!devnode [node|0] [-r]",
    completion = [Expression]
)]
fn devnode(
    session: &Session,
    #[arg(parse = devnode_node, positional)] node: Option<VirtAddr>,
    #[arg(parse = devnode_recurse)] recurse: Option<bool>,
) -> Result<DevNodeDetail> {
    session
        .target
        .inspect_devnode(node, recurse.unwrap_or(false))
}

impl Render for DevNodeDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        // A recursive walk lists the node itself first.
        if self.subtree.is_empty() {
            print_devnode(self);
        } else {
            print_devnode_tree(&self.subtree, self.subtree_truncated);
        }
    }
}

/// Show the device stack for a DEVICE_OBJECT or device node.
///
/// The argument can be any DEVICE_OBJECT in the stack, or the DEVICE_NODE of
/// the stack. The command shows the stack from the top filter down to the PDO,
/// with the !DevObj, !DrvObj, !DevExt, and object name of each device, and a
/// `>` marks the argument. After the stack, the command shows the device node
/// of the PDO.
#[command(
    names = ["!devstack", "devstack"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "device_stack",
    usage = "!devstack <device-object|devnode>"
)]
fn devstack(session: &Session, device_or_node: VirtAddr) -> Result<DeviceStackDetail> {
    session.target.inspect_device_stack(device_or_node)
}

impl Render for DeviceStackDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_device_stack(self);
    }
}

/// Show the PnP device nodes that have problems, pending IRPs, or incomplete
/// starts.
#[command(
    names = ["!pnptriage", "pnptriage"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "pnp_triage"
)]
fn pnptriage(session: &Session) -> Result<PnpTriageDetail> {
    session.target.pnp_triage()
}

impl Render for PnpTriageDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_pnp_triage(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Option<DevNodeRequest> {
        parse_devnode_request(args.iter().copied())
    }

    #[test]
    fn devnode_argument_forms_follow_windbg() {
        assert_eq!(
            parse(&[]),
            Some(DevNodeRequest {
                node: None,
                recursive: false
            })
        );
        assert_eq!(
            parse(&["0"]),
            Some(DevNodeRequest {
                node: None,
                recursive: false
            })
        );
        assert_eq!(
            parse(&["ffff808939817520"]),
            Some(DevNodeRequest {
                node: Some("ffff808939817520".to_string()),
                recursive: false
            })
        );
        assert_eq!(
            parse(&["0", "-r"]),
            Some(DevNodeRequest {
                node: None,
                recursive: true
            })
        );
        assert_eq!(
            parse(&["ffff808939817520", "1"]),
            Some(DevNodeRequest {
                node: Some("ffff808939817520".to_string()),
                recursive: true
            })
        );
        assert_eq!(
            parse(&["-r", "ffff808939817520"]),
            Some(DevNodeRequest {
                node: Some("ffff808939817520".to_string()),
                recursive: true
            })
        );
        for bad in [
            &["-x"][..],
            &["node", "other"][..],
            &["node", "-r", "1"][..],
            &["0", "0"][..],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
