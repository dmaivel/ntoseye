use std::borrow::Cow;

use crate::repl::*;
use crate::target::pnp::{
    DevNodeDetail, DevNodeSummary, DeviceStackDetail, PnpTriageDetail, StateHistoryEntry,
};
use crate::ui;

const HISTORY_DISPLAY_LIMIT: usize = 5;

repl_command! {
    cmd_devnode;
    names: ["!devnode", "devnode"],
    usage: "!devnode [node|0] [-r]",
    summary: "Display a PnP device node and optionally its subtree.",
    details: "With no node (or 0), displays the root device node. -r and the trailing WinDbg-style 1 walk the node's subtree.",
    completion: Expression,
}

repl_command! {
    cmd_devstack;
    names: ["!devstack", "devstack"],
    usage: "!devstack <device-object|devnode>",
    summary: "Display the device stack for a DEVICE_OBJECT or device node.",
    details: "The argument may be a DEVICE_OBJECT or a DEVICE_NODE; the stack is shown from the top filter down to the PDO.",
    completion: Expression,
}

repl_command! {
    cmd_pnptriage;
    names: ["!pnptriage", "pnptriage"],
    usage: "!pnptriage",
    summary: "Report PnP device nodes with problems, pending IRPs, or incomplete starts.",
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevNodeRequest {
    node: Option<String>,
    recursive: bool,
}

fn parse_devnode_request(argv: &[Cow<'_, str>]) -> Option<DevNodeRequest> {
    let mut node = None;
    let mut root = false;
    let mut recursive = false;

    for argument in argv {
        match argument.as_ref() {
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

impl ReplState<'_> {
    fn cmd_devnode(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(request) = parse_devnode_request(&invocation.argv) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let node = match request.node {
            Some(text) => match self.eval_or_report(&text) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            None => None,
        };

        match self.ctx.target.inspect_devnode(node, request.recursive) {
            Ok(detail) if request.recursive => {
                print_devnode_tree(&detail.subtree, detail.subtree_truncated)
            }
            Ok(detail) => print_devnode(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_devstack(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let text = invocation.arg(0).unwrap_or_default();
        let Some(address) = self.eval_or_report(text) else {
            return Ok(());
        };

        match self.ctx.target.inspect_device_stack(address) {
            Ok(stack) => print_device_stack(&stack),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_pnptriage(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match self.ctx.target.pnp_triage() {
            Ok(triage) => print_pnp_triage(&triage),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Option<DevNodeRequest> {
        let argv: Vec<Cow<'_, str>> = args.iter().map(|arg| Cow::Borrowed(*arg)).collect();
        parse_devnode_request(&argv)
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
