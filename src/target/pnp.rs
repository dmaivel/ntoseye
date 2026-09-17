//! PnP structured inspector data (shared by the REPL, Python SDK, and MCP).

use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::VirtAddr;

const MAX_DEVNODES: usize = 4096;
const MAX_DEVICE_STACK: usize = 64;
const DEVICE_NODE_STARTED: u32 = 0x30a;
const DEVICE_NODE_REMOVED: u32 = 0x314;
const DEVICE_NODE_DELETED: u32 = 0x316;

/// One nonzero entry from a `_DEVICE_NODE.StateHistory` ring.
#[derive(Debug, Clone)]
pub struct StateHistoryEntry {
    pub index: u32,
    pub state: u32,
    pub state_name: String,
}

/// The compact device-node identity used by subtree and triage listings.
#[derive(Debug, Clone)]
pub struct DevNodeSummary {
    pub address: VirtAddr,
    pub pdo: VirtAddr,
    pub instance_path: String,
    pub service_name: String,
    pub state: u32,
    pub state_name: String,
    pub problem: u32,
    pub problem_name: Option<String>,
    pub problem_status: u32,
    pub pending_irp: VirtAddr,
    pub depth: u32,
}

/// A decoded `_DEVICE_NODE`, optionally followed by a bounded flat subtree.
#[derive(Debug, Clone)]
pub struct DevNodeDetail {
    pub address: VirtAddr,
    pub pdo: VirtAddr,
    pub parent: VirtAddr,
    pub sibling: VirtAddr,
    pub child: VirtAddr,
    pub instance_path: String,
    pub service_name: String,
    pub state: u32,
    pub state_name: String,
    pub previous_state: u32,
    pub previous_state_name: String,
    pub state_history: Vec<StateHistoryEntry>,
    pub state_history_entry: u32,
    pub flags: u32,
    pub user_flags: u32,
    pub completion_status: u32,
    pub problem: u32,
    pub problem_name: Option<String>,
    pub problem_status: u32,
    pub pending_irp: VirtAddr,
    pub subtree: Vec<DevNodeSummary>,
    pub subtree_truncated: bool,
}

/// One device object in an ordered top-filter-to-PDO device stack.
#[derive(Debug, Clone)]
pub struct DeviceStackEntry {
    pub device_object: VirtAddr,
    pub driver_object: VirtAddr,
    pub driver_name: String,
    pub device_extension: VirtAddr,
    pub object_name: String,
    pub is_argument: bool,
}

/// A bounded device stack and the devnode associated with its PDO, when any.
#[derive(Debug, Clone)]
pub struct DeviceStackDetail {
    pub argument: VirtAddr,
    pub requested_device: VirtAddr,
    pub entries: Vec<DeviceStackEntry>,
    pub pdo_devnode: Option<DevNodeSummary>,
    pub pdo_devnode_error: Option<String>,
    pub truncated: bool,
}

/// PnP triage buckets built from one bounded device-node walk.
#[derive(Debug, Clone)]
pub struct PnpTriageDetail {
    pub problems: Vec<DevNodeSummary>,
    pub not_started: Vec<DevNodeSummary>,
    pub pending_irps: Vec<DevNodeSummary>,
    pub total: u64,
    pub started: u64,
    pub truncated: bool,
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

struct WalkResult {
    nodes: Vec<DevNode>,
    truncated: bool,
}

struct DeviceStack {
    entries: Vec<DeviceInfo>,
    pdo: DeviceInfo,
    truncated: bool,
}

struct DevNodeReader<'a> {
    target: &'a Target,
    states: HashMap<u32, String>,
}

impl<'a> DevNodeReader<'a> {
    fn new(target: &'a Target) -> Self {
        Self {
            states: state_names(target),
            target,
        }
    }

    fn root(&self) -> Result<VirtAddr> {
        self.target
            .guest()?
            .ntoskrnl
            .symbol("IopRootDeviceNode")?
            .read::<VirtAddr>()
    }

    fn read_node(&self, address: VirtAddr) -> Result<DevNode> {
        let node = self
            .target
            .guest()?
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

    fn walk(&self, root: VirtAddr, include_root_sibling: bool) -> Result<WalkResult> {
        let mut pending = vec![(root, include_root_sibling)];
        let mut seen = HashSet::with_capacity(64);
        let mut nodes = Vec::new();
        let mut truncated = false;

        while let Some((address, include_sibling)) = pending.pop() {
            if address.is_zero() || !seen.insert(address.0) {
                continue;
            }
            if nodes.len() >= MAX_DEVNODES {
                truncated = true;
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
        Ok(WalkResult { nodes, truncated })
    }

    fn walk_tree(&self, root: VirtAddr) -> Result<WalkResult> {
        self.walk(root, true)
    }

    fn walk_subtree(&self, root: VirtAddr) -> Result<WalkResult> {
        self.walk(root, false)
    }

    fn read_device(&self, address: VirtAddr) -> Result<DeviceInfo> {
        let object = self
            .target
            .guest()?
            .ntoskrnl
            .types()
            .struct_at("_DEVICE_OBJECT", address)?;
        let device_object_extension = object.read_pointer("DeviceObjectExtension")?;
        let (attached_to, device_node) = if device_object_extension.is_zero() {
            (VirtAddr(0), VirtAddr(0))
        } else {
            let extension = self
                .target
                .guest()?
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
        let mut truncated = false;
        while !current.is_zero() {
            if downward.len() >= MAX_DEVICE_STACK {
                truncated = true;
                break;
            }
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
        while !current.is_zero() {
            if upward.len() >= MAX_DEVICE_STACK {
                truncated = true;
                break;
            }
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
            truncated,
        })
    }
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

fn history_entries(node: &DevNode, states: &HashMap<u32, String>) -> Vec<StateHistoryEntry> {
    let length = node.state_history.len();
    if length == 0 {
        return Vec::new();
    }

    let next = (node.state_history_entry as usize) % length;
    (0..length)
        .map(|offset| (next + offset) % length)
        .filter_map(|index| {
            let state = node.state_history[index];
            (state != 0).then(|| StateHistoryEntry {
                index: index as u32,
                state,
                state_name: state_label(state, states),
            })
        })
        .collect()
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

fn problem_label(code: u32) -> Option<String> {
    (code != 0).then(|| {
        problem_name(code)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{code:#x}"))
    })
}

fn summary(node: &DevNode, states: &HashMap<u32, String>) -> DevNodeSummary {
    DevNodeSummary {
        address: node.address,
        pdo: node.pdo,
        instance_path: node.instance_path.clone(),
        service_name: node.service_name.clone(),
        state: node.state,
        state_name: state_label(node.state, states),
        problem: node.problem,
        problem_name: problem_label(node.problem),
        problem_status: node.problem_status,
        pending_irp: node.pending_irp,
        depth: node.level,
    }
}

/// Decode the selected `_DEVICE_NODE`; `None` or a zero address selects
/// `IopRootDeviceNode`.  When `recurse` is true, `subtree` contains the same
/// bounded depth-first walk used by `!devnode -r`; unreadable node fields make
/// the operation fail rather than silently dropping a node.
fn inspect_devnode_impl(
    target: &Target,
    node: Option<VirtAddr>,
    recurse: bool,
) -> Result<DevNodeDetail> {
    let reader = DevNodeReader::new(target);
    let root = reader.root()?;
    let address = node.filter(|address| !address.is_zero()).unwrap_or(root);
    let decoded = reader.read_node(address)?;
    let (subtree, subtree_truncated) = if recurse {
        let walked = reader.walk_subtree(address)?;
        (
            walked
                .nodes
                .iter()
                .map(|node| summary(node, &reader.states))
                .collect(),
            walked.truncated,
        )
    } else {
        (Vec::new(), false)
    };
    let state_history = history_entries(&decoded, &reader.states);

    Ok(DevNodeDetail {
        address: decoded.address,
        pdo: decoded.pdo,
        parent: decoded.parent,
        sibling: decoded.sibling,
        child: decoded.child,
        instance_path: decoded.instance_path,
        service_name: decoded.service_name,
        state: decoded.state,
        state_name: state_label(decoded.state, &reader.states),
        previous_state: decoded.previous_state,
        previous_state_name: state_label(decoded.previous_state, &reader.states),
        state_history,
        state_history_entry: decoded.state_history_entry,
        flags: decoded.flags,
        user_flags: decoded.user_flags,
        completion_status: decoded.completion_status,
        problem: decoded.problem,
        problem_name: problem_label(decoded.problem),
        problem_status: decoded.problem_status,
        pending_irp: decoded.pending_irp,
        subtree,
        subtree_truncated,
    })
}

impl Target {
    /// Decode one `_DEVICE_NODE` and, optionally, its bounded subtree. Every
    /// scalar/string field is read from the PDB-described layout; layout or
    /// memory failures are returned so an unavailable field is not presented as
    /// a valid value.
    pub fn inspect_devnode(&self, node: Option<VirtAddr>, recurse: bool) -> Result<DevNodeDetail> {
        inspect_devnode_impl(self, node, recurse)
    }

    /// Decode a device stack from a `_DEVICE_OBJECT` (or pointer to one), or
    /// resolve a `_DEVICE_NODE` argument through its PDO. Entries are ordered
    /// from the uppermost filter down to the PDO; a bounded walk sets
    /// `truncated` instead of losing that termination information.
    pub fn inspect_device_stack(&self, device_or_node: VirtAddr) -> Result<DeviceStackDetail> {
        let reader = DevNodeReader::new(self);
        let requested = match self.inspect_device_object(device_or_node) {
            Ok(device) => device.object,
            Err(_) => {
                let node = reader.read_node(device_or_node)?;
                if node.pdo.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "device node {:#x} has no physical device object",
                        device_or_node.0
                    )));
                }
                node.pdo
            }
        };

        let stack = reader.device_stack(requested)?;
        let entries = stack
            .entries
            .iter()
            .map(|device| DeviceStackEntry {
                device_object: device.device,
                driver_object: device.driver_object,
                driver_name: self
                    .inspect_driver_object(device.driver_object)
                    .ok()
                    .and_then(|detail| detail.name)
                    .unwrap_or_default(),
                device_extension: device.device_extension,
                object_name: self
                    .inspect_object_header(device.device)
                    .ok()
                    .and_then(|detail| detail.name)
                    .unwrap_or_default(),
                is_argument: device.device == requested,
            })
            .collect();
        let (pdo_devnode, pdo_devnode_error) = if stack.pdo.device_node.is_zero() {
            (None, None)
        } else {
            match reader.read_node(stack.pdo.device_node) {
                Ok(node) => (Some(summary(&node, &reader.states)), None),
                Err(error) => (None, Some(error.to_string())),
            }
        };

        Ok(DeviceStackDetail {
            argument: device_or_node,
            requested_device: requested,
            entries,
            pdo_devnode,
            pdo_devnode_error,
            truncated: stack.truncated,
        })
    }

    /// Walk the root device-node tree once and partition summaries into nodes
    /// with problem codes, nodes not in a started state (excluding removed or
    /// deleted nodes), and nodes with pending PnP IRPs. The 4096-node bound is
    /// reported in `truncated`.
    pub fn pnp_triage(&self) -> Result<PnpTriageDetail> {
        let reader = DevNodeReader::new(self);
        let root = reader.root()?;
        let walked = reader.walk_tree(root)?;
        let summaries: Vec<DevNodeSummary> = walked
            .nodes
            .iter()
            .map(|node| summary(node, &reader.states))
            .collect();
        let started_code = state_code(&reader.states, "DeviceNodeStarted", DEVICE_NODE_STARTED);
        let gone = [
            state_code(&reader.states, "DeviceNodeDeleted", DEVICE_NODE_DELETED),
            state_code(&reader.states, "DeviceNodeRemoved", DEVICE_NODE_REMOVED),
        ];
        let problems = summaries
            .iter()
            .filter(|node| node.problem != 0)
            .cloned()
            .collect();
        let not_started = summaries
            .iter()
            .filter(|node| node.state != started_code && !gone.contains(&node.state))
            .cloned()
            .collect();
        let pending_irps = summaries
            .iter()
            .filter(|node| !node.pending_irp.is_zero())
            .cloned()
            .collect();
        let started = summaries
            .iter()
            .filter(|node| node.state == started_code)
            .count() as u64;

        Ok(PnpTriageDetail {
            problems,
            not_started,
            pending_irps,
            total: summaries.len() as u64,
            started,
            truncated: walked.truncated,
        })
    }
}

fn state_code(states: &HashMap<u32, String>, name: &str, fallback: u32) -> u32 {
    if states.is_empty() {
        return fallback;
    }
    states
        .iter()
        .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
        .map_or(fallback, |(code, _)| *code)
}
