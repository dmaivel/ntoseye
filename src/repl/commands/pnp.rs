use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::Guest;
use crate::repl::*;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;

const MAX_DEVNODES: usize = 4096;
const MAX_DEVICE_STACK: usize = 64;
const HISTORY_DISPLAY_LIMIT: usize = 5;
const DEVICE_NODE_STARTED: u32 = 0x30a;
const DEVICE_NODE_REMOVED: u32 = 0x314;
const DEVICE_NODE_DELETED: u32 = 0x316;

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

#[derive(Debug, Clone)]
struct DevNode {
    address: VirtAddr,
    parent: VirtAddr,
    sibling: VirtAddr,
    child: VirtAddr,
    pdo: VirtAddr,
    instance_path: String,
    service_name: String,
    state: u32,
    previous_state: u32,
    state_history: Vec<u32>,
    state_history_entry: u32,
    problem: u32,
    problem_status: u32,
    flags: u32,
    user_flags: u32,
    pending_irp: VirtAddr,
    completion_status: u32,
    level: u32,
}

#[derive(Debug, Clone)]
struct DeviceInfo {
    device: VirtAddr,
    driver_object: VirtAddr,
    device_extension: VirtAddr,
    attached_to: VirtAddr,
    attached_device: VirtAddr,
    device_node: VirtAddr,
}

struct DeviceStack {
    entries: Vec<DeviceInfo>,
    pdo: DeviceInfo,
}

struct DevNodeReader<'a> {
    guest: &'a Guest,
    states: HashMap<u32, String>,
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

fn state_names(target: &Target) -> HashMap<u32, String> {
    target
        .symbols
        .find_enum_across_modules(target.current_dtb(), "_PNP_DEVNODE_STATE")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, value)| u32::try_from(value).ok().map(|value| (value, name)))
        .collect()
}

fn state_label(code: u32, states: &HashMap<u32, String>) -> String {
    states
        .get(&code)
        .cloned()
        .unwrap_or_else(|| format!("{code:#x}"))
}

fn state_text(code: u32, states: &HashMap<u32, String>) -> String {
    states
        .get(&code)
        .map(|name| format!("{name} ({code:#x})"))
        .unwrap_or_else(|| format!("{code:#x}"))
}

/// The enum value named `name` in the build's `_PNP_DEVNODE_STATE`, or
/// `fallback` (the current numbering) when the PDB has no enum.
fn state_code(states: &HashMap<u32, String>, name: &str, fallback: u32) -> u32 {
    if states.is_empty() {
        return fallback;
    }
    states
        .iter()
        .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
        .map_or(fallback, |(code, _)| *code)
}

fn problem_text(code: u32) -> String {
    problem_name(code)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{code:#x}"))
}

fn compact_devnode_line(node: &DevNode, states: &HashMap<u32, String>) -> String {
    let mut line = format!(
        "DevNode {}  PDO {}  {}  [{}]  {}",
        ui::addr(node.address.0),
        ui::addr(node.pdo.0),
        node.instance_path,
        node.service_name,
        state_label(node.state, states)
    );
    if node.problem != 0 {
        line.push_str(&format!(
            "  problem={} status={:#x}",
            problem_text(node.problem),
            node.problem_status
        ));
    }
    line
}

fn history_tail(node: &DevNode) -> Vec<(usize, u32)> {
    let length = node.state_history.len();
    if length == 0 {
        return Vec::new();
    }

    let next = (node.state_history_entry as usize) % length;
    let mut ordered = Vec::with_capacity(length);
    for offset in 0..length {
        let index = (next + offset) % length;
        let state = node.state_history[index];
        if state != 0 {
            ordered.push((index, state));
        }
    }
    let first = ordered.len().saturating_sub(HISTORY_DISPLAY_LIMIT);
    ordered.into_iter().skip(first).collect()
}

fn print_devnode(node: &DevNode, states: &HashMap<u32, String>) {
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
    outln!("  State = {}", state_text(node.state, states));
    outln!(
        "  Previous State = {}",
        state_text(node.previous_state, states)
    );
    for (index, state) in history_tail(node) {
        outln!("  StateHistory[{index}] = {}", state_text(state, states));
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
            problem_text(node.problem),
            node.problem,
            node.problem_status
        );
    }
    if !node.pending_irp.is_zero() {
        outln!("  PendingIrp {}", ui::addr(node.pending_irp.0));
    }
}

fn print_devnode_summary(node: &DevNode, states: &HashMap<u32, String>) {
    outln!("!DevNode {} :", ui::addr(node.address.0));
    outln!("  DeviceInst is \"{}\"", node.instance_path);
    outln!("  ServiceName is \"{}\"", node.service_name);
    outln!("  State = {}", state_text(node.state, states));
}

fn print_devnode_tree(nodes: &[DevNode], states: &HashMap<u32, String>) {
    let top = nodes.first().map_or(0, |node| node.level);
    for node in nodes {
        let indentation = "  ".repeat((node.level.saturating_sub(top) as usize).min(64));
        outln!("{}{}", indentation, compact_devnode_line(node, states));
    }
}

fn driver_name(target: &Target, address: VirtAddr) -> String {
    target
        .inspect_driver_object(address)
        .ok()
        .and_then(|detail| detail.name)
        .unwrap_or_default()
}

fn object_name(target: &Target, address: VirtAddr) -> String {
    target
        .inspect_object_header(address)
        .ok()
        .and_then(|detail| detail.name)
        .unwrap_or_default()
}

impl<'a> DevNodeReader<'a> {
    fn new(guest: &'a Guest, states: HashMap<u32, String>) -> Self {
        Self { guest, states }
    }

    fn root(&self) -> Result<VirtAddr> {
        self.guest
            .ntoskrnl
            .symbol("IopRootDeviceNode")?
            .read::<VirtAddr>()
    }

    fn read_node(&self, address: VirtAddr) -> Result<DevNode> {
        let node = self
            .guest
            .ntoskrnl
            .types()
            .struct_at("_DEVICE_NODE", address)?;
        let history_bytes = node.read_field_bytes("StateHistory", 0x100)?;
        let state_history = history_bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bytes| u32::from_le_bytes(*bytes))
            .collect();

        Ok(DevNode {
            address,
            parent: node.read_pointer("Parent")?,
            sibling: node.read_pointer("Sibling")?,
            child: node.read_pointer("Child")?,
            pdo: node.read_pointer("PhysicalDeviceObject")?,
            instance_path: node.unicode_string("InstancePath")?,
            service_name: node.unicode_string("ServiceName")?,
            state: node.read_field("State")?,
            previous_state: node.read_field("PreviousState")?,
            state_history,
            state_history_entry: node.read_field("StateHistoryEntry")?,
            problem: node.read_field("Problem")?,
            problem_status: node.read_field("ProblemStatus")?,
            flags: node.read_field("Flags")?,
            user_flags: node.read_field("UserFlags")?,
            pending_irp: node.read_pointer("PendingIrp")?,
            completion_status: node.read_field("CompletionStatus")?,
            level: node.read_field("Level")?,
        })
    }

    fn walk(&self, root: VirtAddr, include_root_sibling: bool) -> Result<Vec<DevNode>> {
        let mut pending = vec![(root, include_root_sibling)];
        let mut seen = HashSet::new();
        let mut nodes = Vec::new();

        while let Some((address, include_sibling)) = pending.pop() {
            if nodes.len() >= MAX_DEVNODES || address.is_zero() || !seen.insert(address.0) {
                continue;
            }
            let node = self.read_node(address)?;
            let sibling = node.sibling;
            let child = node.child;
            nodes.push(node);

            if include_sibling && !sibling.is_zero() {
                pending.push((sibling, true));
            }
            if !child.is_zero() {
                pending.push((child, true));
            }
        }
        Ok(nodes)
    }

    fn walk_tree(&self, root: VirtAddr) -> Result<Vec<DevNode>> {
        self.walk(root, true)
    }

    fn walk_subtree(&self, root: VirtAddr) -> Result<Vec<DevNode>> {
        self.walk(root, false)
    }

    fn read_device(&self, address: VirtAddr) -> Result<DeviceInfo> {
        let object = self
            .guest
            .ntoskrnl
            .types()
            .struct_at("_DEVICE_OBJECT", address)?;
        let device_object_extension = object.read_pointer("DeviceObjectExtension")?;
        let (attached_to, device_node) = if device_object_extension.is_zero() {
            (VirtAddr(0), VirtAddr(0))
        } else {
            let extension = self
                .guest
                .ntoskrnl
                .types()
                .struct_at("_DEVOBJ_EXTENSION", device_object_extension)?;
            (
                extension.read_pointer("AttachedTo")?,
                extension.read_pointer("DeviceNode")?,
            )
        };

        Ok(DeviceInfo {
            device: address,
            driver_object: object.read_pointer("DriverObject")?,
            device_extension: object.read_pointer("DeviceExtension")?,
            attached_to,
            attached_device: object.read_pointer("AttachedDevice")?,
            device_node,
        })
    }

    fn device_stack(&self, requested: VirtAddr) -> Result<DeviceStack> {
        let mut downward = Vec::new();
        let mut seen = HashSet::new();
        let mut current = requested;
        while !current.is_zero() && downward.len() < MAX_DEVICE_STACK {
            if !seen.insert(current.0) {
                break;
            }
            let device = self.read_device(current)?;
            let next = device.attached_to;
            downward.push(device);
            if next.is_zero() {
                break;
            }
            current = next;
        }

        let Some(pdo) = downward.last().cloned() else {
            return Err(Error::DebugInfo("empty device stack".to_string()));
        };
        let known: HashMap<u64, DeviceInfo> = downward
            .iter()
            .cloned()
            .map(|device| (device.device.0, device))
            .collect();
        let mut upward = Vec::new();
        let mut seen = HashSet::new();
        let mut current = pdo.device;
        while !current.is_zero() && upward.len() < MAX_DEVICE_STACK {
            if !seen.insert(current.0) {
                break;
            }
            let device = match known.get(&current.0) {
                Some(device) => device.clone(),
                None => self.read_device(current)?,
            };
            let next = device.attached_device;
            upward.push(device);
            if next.is_zero() {
                break;
            }
            current = next;
        }
        upward.reverse();
        Ok(DeviceStack {
            entries: upward,
            pdo,
        })
    }
}

const CM_PROB_NAMES: &[(u32, &str)] = &[
    (1, "CM_PROB_NOT_CONFIGURED"),
    (2, "CM_PROB_DEVLOADER_FAILED"),
    (3, "CM_PROB_OUT_OF_MEMORY"),
    (4, "CM_PROB_ENTRY_IS_WRONG_TYPE"),
    (5, "CM_PROB_LACKED_ARBITRATOR"),
    (6, "CM_PROB_BOOT_CONFIG_CONFLICT"),
    (7, "CM_PROB_FAILED_FILTER"),
    (8, "CM_PROB_DEVLOADER_NOT_FOUND"),
    (9, "CM_PROB_INVALID_DATA"),
    (10, "CM_PROB_FAILED_START"),
    (11, "CM_PROB_LIAR"),
    (12, "CM_PROB_NORMAL_CONFLICT"),
    (13, "CM_PROB_NOT_VERIFIED"),
    (14, "CM_PROB_NEED_RESTART"),
    (15, "CM_PROB_REENUMERATION"),
    (16, "CM_PROB_PARTIAL_LOG_CONF"),
    (17, "CM_PROB_UNKNOWN_RESOURCE"),
    (18, "CM_PROB_REINSTALL"),
    (19, "CM_PROB_REGISTRY"),
    (20, "CM_PROB_VXDLDR"),
    (21, "CM_PROB_WILL_BE_REMOVED"),
    (22, "CM_PROB_DISABLED"),
    (23, "CM_PROB_DEVLOADER_NOT_READY"),
    (24, "CM_PROB_DEVICE_NOT_THERE"),
    (25, "CM_PROB_MOVED"),
    (26, "CM_PROB_TOO_EARLY"),
    (27, "CM_PROB_NO_VALID_LOG_CONF"),
    (28, "CM_PROB_FAILED_INSTALL"),
    (29, "CM_PROB_HARDWARE_DISABLED"),
    (30, "CM_PROB_CANT_SHARE_IRQ"),
    (31, "CM_PROB_FAILED_ADD"),
    (32, "CM_PROB_DISABLED_SERVICE"),
    (33, "CM_PROB_TRANSLATION_FAILED"),
    (34, "CM_PROB_NO_SOFTCONFIG"),
    (35, "CM_PROB_BIOS_TABLE"),
    (36, "CM_PROB_IRQ_TRANSLATION_FAILED"),
    (37, "CM_PROB_FAILED_DRIVER_ENTRY"),
    (38, "CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD"),
    (39, "CM_PROB_DRIVER_FAILED_LOAD"),
    (40, "CM_PROB_DRIVER_SERVICE_KEY_INVALID"),
    (41, "CM_PROB_LEGACY_SERVICE_NO_DEVICES"),
    (42, "CM_PROB_DUPLICATE_DEVICE"),
    (43, "CM_PROB_FAILED_POST_START"),
    (44, "CM_PROB_HALTED"),
    (45, "CM_PROB_PHANTOM"),
    (46, "CM_PROB_SYSTEM_SHUTDOWN"),
    (47, "CM_PROB_HELD_FOR_EJECT"),
    (48, "CM_PROB_DRIVER_BLOCKED"),
    (49, "CM_PROB_REGISTRY_TOO_LARGE"),
    (50, "CM_PROB_SETPROPERTIES_FAILED"),
    (51, "CM_PROB_WAITING_ON_DEPENDENCY"),
    (52, "CM_PROB_UNSIGNED_DRIVER"),
    (53, "CM_PROB_USED_BY_DEBUGGER"),
    (54, "CM_PROB_DEVICE_RESET"),
    (55, "CM_PROB_CONSOLE_LOCKED"),
    (56, "CM_PROB_NEED_CLASS_CONFIG"),
    (57, "CM_PROB_GUEST_ASSIGNMENT_FAILED"),
];

fn problem_name(code: u32) -> Option<&'static str> {
    CM_PROB_NAMES
        .iter()
        .find_map(|(value, name)| (*value == code).then_some(*name))
}

impl ReplState<'_> {
    fn cmd_devnode(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(request) = parse_devnode_request(&invocation.argv) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let states = state_names(&self.ctx.target);
        let guest = match self.ctx.target.guest() {
            Ok(guest) => guest,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let reader = DevNodeReader::new(guest, states);
        let root = match reader.root() {
            Ok(root) => root,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let address = match request.node {
            Some(text) => match Expr::eval_with_radix(&text, &self.ctx.target, self.radix) {
                Ok(address) if !address.is_zero() => address,
                Ok(_) => root,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => root,
        };

        if request.recursive {
            match reader.walk_subtree(address) {
                Ok(nodes) => print_devnode_tree(&nodes, &reader.states),
                Err(error) => error!("{error}"),
            }
        } else {
            match reader.read_node(address) {
                Ok(node) => print_devnode(&node, &reader.states),
                Err(error) => error!("{error}"),
            }
        }
        Ok(())
    }

    fn cmd_devstack(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let text = invocation.arg(0).unwrap_or_default();
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let states = state_names(&self.ctx.target);
        let guest = match self.ctx.target.guest() {
            Ok(guest) => guest,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let reader = DevNodeReader::new(guest, states);
        let requested = match self.ctx.target.inspect_device_object(address) {
            Ok(device) => device.object,
            Err(_) => {
                let node = match reader.read_node(address) {
                    Ok(node) => node,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                };
                if node.pdo.is_zero() {
                    error!(
                        "device node {} has no physical device object",
                        ui::addr(address.0)
                    );
                    return Ok(());
                }
                node.pdo
            }
        };

        let stack = match reader.device_stack(requested) {
            Ok(stack) => stack,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        outln!(
            "  {:<18} {:<18} {:<18}{}",
            "!DevObj",
            "!DrvObj",
            "!DevExt",
            "ObjectName"
        );
        for device in &stack.entries {
            let marker = if device.device == requested { ">" } else { " " };
            outln!(
                "{} {:<18} {:<18} {:<18}{}",
                marker,
                ui::addr(device.device.0),
                driver_name(&self.ctx.target, device.driver_object),
                ui::addr(device.device_extension.0),
                object_name(&self.ctx.target, device.device)
            );
        }

        if stack.pdo.device_node.is_zero() {
            outln!("!DevNode {}", ui::addr(0));
        } else {
            match reader.read_node(stack.pdo.device_node) {
                Ok(node) => print_devnode_summary(&node, &reader.states),
                Err(error) => error!("{error}"),
            }
        }
        Ok(())
    }

    fn cmd_pnptriage(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let states = state_names(&self.ctx.target);
        let guest = match self.ctx.target.guest() {
            Ok(guest) => guest,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let reader = DevNodeReader::new(guest, states);
        let root = match reader.root() {
            Ok(root) => root,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let nodes = match reader.walk_tree(root) {
            Ok(nodes) => nodes,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };

        let problems: Vec<&DevNode> = nodes.iter().filter(|node| node.problem != 0).collect();
        let started_code = state_code(&reader.states, "DeviceNodeStarted", DEVICE_NODE_STARTED);
        let gone = [
            state_code(&reader.states, "DeviceNodeDeleted", DEVICE_NODE_DELETED),
            state_code(&reader.states, "DeviceNodeRemoved", DEVICE_NODE_REMOVED),
        ];
        let not_started: Vec<&DevNode> = nodes
            .iter()
            .filter(|node| node.state != started_code && !gone.contains(&node.state))
            .collect();
        let pending: Vec<&DevNode> = nodes
            .iter()
            .filter(|node| !node.pending_irp.is_zero())
            .collect();
        let started = nodes
            .iter()
            .filter(|node| node.state == started_code)
            .count();

        outln!("Problem devnodes:");
        if problems.is_empty() {
            outln!("  none");
        } else {
            for node in &problems {
                outln!("  {}", compact_devnode_line(node, &reader.states));
            }
        }

        outln!("Devnodes not started:");
        if not_started.is_empty() {
            outln!("  none");
        } else {
            for node in &not_started {
                outln!("  {}", compact_devnode_line(node, &reader.states));
            }
        }

        outln!("Devnodes with pending PnP IRPs:");
        if pending.is_empty() {
            outln!("  none");
        } else {
            for node in &pending {
                outln!(
                    "  {}  pending={}",
                    compact_devnode_line(node, &reader.states),
                    ui::addr(node.pending_irp.0)
                );
            }
        }

        outln!(
            "{} devnode(s): {} started, {} with problems, {} not started, {} with pending IRPs",
            nodes.len(),
            started,
            problems.len(),
            not_started.len(),
            pending.len()
        );
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
