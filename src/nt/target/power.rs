//! Power management (`!poaction`, `!podev`, `!popolicy`, and what `!analyze`
//! reads for DRIVER_POWER_STATE_FAILURE), from the kernel's own structures
//! and typed by its PDB.
//!
//! `nt!PopAction` is the system power action in progress. Each power IRP
//! that `PoRequestPowerIrp` allocates has a `_POP_IRP_DATA` on
//! `nt!PopIrpList` until it completes: the IRP, the PDO, the device the IRP
//! was sent to, its minor function and power state, and `WatchdogStart`, the
//! unbiased interrupt time at which the power manager armed the watchdog
//! that bugchecks with 0x9F subtype 0x3 when a driver holds the IRP too
//! long. The threads that pass power IRPs to drivers are on
//! `nt!PopIrpThreadList`, each with the IRP and the device it is working
//! on. A device's own power state is in its `_DEVOBJ_EXTENSION`: the last
//! system and device states its driver set with `PoSetPowerState`, and,
//! when the driver registered for idle detection, the idle counters.

use std::cell::OnceCell;

use super::{DiagnosticValue, Target};
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::bugchecks::module_filename;
use crate::nt::guest::ModuleInfo;
use crate::nt::kuser_shared::KuserSharedData;
use crate::nt::layout::{ParsedType, StructRef, Types};
use crate::nt::target::object::{IrpInfo, SL_PENDING_RETURNED};
use crate::nt::target::pnp::DeviceStackDetail;
use ntoseye_macros::record;

/// More power IRPs than the power manager has allocated at once.
const MAX_POWER_IRPS: usize = 1024;
/// More IRP worker threads than the power manager starts.
const MAX_IRP_WORKERS: usize = 256;
/// `IO_TYPE_IRP`, `IO_TYPE_DEVICE`, and `IO_TYPE_DRIVER`: the `Type` of an
/// IRP, a device object, and a driver object.
const IO_TYPE_IRP: u64 = 6;
const IO_TYPE_DEVICE: u64 = 3;
const IO_TYPE_DRIVER: u64 = 4;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MN_WAIT_WAKE: u8 = 0;
pub const IRP_MN_POWER_SEQUENCE: u8 = 1;
pub const IRP_MN_SET_POWER: u8 = 2;
pub const IRP_MN_QUERY_POWER: u8 = 3;
/// The `POWER_STATE_TYPE` of a `POWER_STATE` that holds a device state;
/// `SystemPowerState` (0) is the other.
const DEVICE_POWER_STATE: u64 = 1;
/// `TRIAGE_9F_POWER.Signature`, as `PopIrpWatchdogBugcheck` sets it.
const TRIAGE_9F_POWER_SIGNATURE: u64 = 0x8000;
/// `_DEVOBJ_EXTENSION.PowerFlags` holds the system state its driver last set
/// in bits 0-3 and the device state in bits 4-7.
const POWER_FLAGS_SYSTEM_STATE: u32 = 0x0f;
const POWER_FLAGS_DEVICE_STATE: u32 = 0xf0;
/// `DO_POWER_PAGABLE` and `DO_POWER_INRUSH` in `DEVICE_OBJECT.Flags`.
pub const DO_POWER_PAGABLE: u32 = 0x2000;
pub const DO_POWER_INRUSH: u32 = 0x4000;

/// The `POWER_ACTION_*` flags of a power action or an action policy.
const POWER_ACTION_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "QUERY_ALLOWED"),
    (0x0000_0002, "UI_ALLOWED"),
    (0x0000_0004, "OVERRIDE_APPS"),
    (0x0000_0008, "HIBERBOOT"),
    (0x0000_0010, "USER_NOTIFY"),
    (0x0000_0020, "DOZE_TO_HIBERNATE"),
    (0x0100_0000, "ACPI_CRITICAL"),
    (0x0200_0000, "ACPI_USER_NOTIFY"),
    (0x0400_0000, "DIRECTED_DRIPS"),
    (0x0800_0000, "PSEUDO_TRANSITION"),
    (0x1000_0000, "LIGHTEST_FIRST"),
    (0x2000_0000, "LOCK_CONSOLE"),
    (0x4000_0000, "DISABLE_WAKES"),
    (0x8000_0000, "CRITICAL"),
];

/// The `EventCode` bits of a `POWER_ACTION_POLICY`.
const POWER_EVENT_CODES: &[(u32, &str)] = &[
    (0x0000_0001, "USER_NOTIFY_TEXT"),
    (0x0000_0002, "USER_NOTIFY_SOUND"),
    (0x0000_0004, "USER_NOTIFY_EXEC"),
    (0x0000_0008, "USER_NOTIFY_BUTTON"),
    (0x0000_0010, "USER_NOTIFY_SHUTDOWN"),
    (0x0000_0020, "USER_NOTIFY_FORCED_SHUTDOWN"),
    (0x8000_0000, "FORCE_TRIGGER_RESET"),
];

/// The names of the bits of `value` that `names` knows, in bit order.
pub fn flag_names(value: u32, names: &[(u32, &'static str)]) -> Vec<&'static str> {
    names
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// [`flag_names`] of a power action's or action policy's `Flags`.
pub fn power_action_flag_names(flags: u32) -> Vec<&'static str> {
    flag_names(flags, POWER_ACTION_FLAGS)
}

/// [`flag_names`] of an action policy's `EventCode`.
pub fn power_event_code_names(code: u32) -> Vec<&'static str> {
    flag_names(code, POWER_EVENT_CODES)
}

/// `PopAction.State`: where the power manager is in carrying out a system
/// power action.
pub fn power_action_state_name(state: u8) -> Option<&'static str> {
    match state {
        0 => Some("Idle"),
        1 => Some("NewRequest"),
        2 => Some("Callout"),
        3 => Some("SetSystemState"),
        _ => None,
    }
}

/// `SYSTEM_POWER_POLICY.DynamicThrottle` (`PO_THROTTLE_*`).
pub fn dynamic_throttle_name(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("None"),
        1 => Some("Constant"),
        2 => Some("Degrade"),
        3 => Some("Adaptive"),
        _ => None,
    }
}

/// The name of a power IRP's minor function.
pub fn power_minor_name(minor: u8) -> Option<&'static str> {
    match minor {
        IRP_MN_WAIT_WAKE => Some("IRP_MN_WAIT_WAKE"),
        IRP_MN_POWER_SEQUENCE => Some("IRP_MN_POWER_SEQUENCE"),
        IRP_MN_SET_POWER => Some("IRP_MN_SET_POWER"),
        IRP_MN_QUERY_POWER => Some("IRP_MN_QUERY_POWER"),
        _ => None,
    }
}

/// A value of one of the kernel's power enums, with its name when the PDB
/// has one, less the enum's common prefix (`Working` for
/// `PowerSystemWorking`, `D3` for `PowerDeviceD3`).
#[record(impl)]
#[derive(PartialEq, Eq)]
pub struct PowerEnum {
    pub value: u64,
    /// The name; `None` when the PDB has no name for the value.
    pub name: Option<String>,
}

#[record]
impl PowerEnum {
    /// The name, or the value in hex.
    #[record(getter)]
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{:#x}", self.value))
    }
}

/// The power state a power IRP or a stack location asks for: a `system`
/// or a `device` state.
#[record(tagged)]
#[derive(PartialEq, Eq)]
pub enum PowerState {
    System(PowerEnum),
    Device(PowerEnum),
}

impl PowerState {
    pub fn label(&self) -> String {
        match self {
            Self::System(state) | Self::Device(state) => state.label(),
        }
    }
}

/// A driver, found from one of its device objects or its driver object.
#[record]
#[derive(PartialEq, Eq)]
pub struct DeviceDriver {
    pub driver_object: VirtAddr,
    /// `\Driver\viostor`; empty when the driver object has no name.
    pub name: String,
    pub driver_start: VirtAddr,
    /// The loaded module that holds `driver_start`, such as `viostor.sys`.
    pub module: Option<String>,
}

impl DeviceDriver {
    /// The module, else the driver object's name, else its address.
    pub fn label(&self) -> String {
        match (&self.module, self.name.is_empty()) {
            (Some(module), true) => module.clone(),
            (Some(module), false) => format!("{} ({module})", self.name),
            (None, false) => self.name.clone(),
            (None, true) => format!("driver object {:#x}", self.driver_object.0),
        }
    }
}

/// Where an IRP is pending: the driver of its current stack location.
#[record]
pub struct IrpHolder {
    /// `CurrentLocation`, counted from 1 as `!irp` does.
    pub location: u8,
    pub stack_count: u8,
    pub stack_location: VirtAddr,
    #[record(hex)]
    pub major_function: u8,
    #[record(hex)]
    pub minor_function: u8,
    /// The state that location's power request asks for.
    pub state: Option<PowerState>,
    /// The location's driver returned `STATUS_PENDING` for it.
    pub pending_returned: bool,
    pub device: VirtAddr,
    pub driver: DiagnosticValue<DeviceDriver>,
}

/// A power IRP the power manager allocated (`_POP_IRP_DATA`).
#[record(impl)]
pub struct PowerIrp {
    pub data: VirtAddr,
    pub irp: VirtAddr,
    pub pdo: VirtAddr,
    /// The device `PoRequestPowerIrp` sent the IRP to, the top of the PDO's
    /// stack.
    pub target_device: VirtAddr,
    /// The device the power manager passed it to last, or 0.
    pub current_device: VirtAddr,
    pub minor_function: u8,
    pub state: PowerState,
    /// The IRP is part of a system power transition.
    pub system_transition: bool,
    /// `WatchdogState`: whether the watchdog for the IRP runs.
    pub watchdog: PowerEnum,
    /// How long ago the watchdog was armed, in 100 ns units: how long the
    /// drivers have had the IRP. `None` when the watchdog never ran or the
    /// current time is unreadable.
    pub pending: Option<u64>,
    /// Where the IRP is now, or why that is unknown.
    pub holder: DiagnosticValue<IrpHolder>,
}

#[record]
impl PowerIrp {
    /// `IRP_MN_SET_POWER`, `IRP_MN_QUERY_POWER`, `IRP_MN_WAIT_WAKE`, or
    /// `IRP_MN_POWER_SEQUENCE`.
    #[record(getter)]
    pub fn minor_name(&self) -> Option<&'static str> {
        power_minor_name(self.minor_function)
    }

    /// How long ago the watchdog was armed, in milliseconds.
    #[record(getter)]
    pub fn pending_ms(&self) -> Option<u64> {
        self.pending.map(|pending| pending / 10_000)
    }
}

/// An entry on a list of `_POP_IRP_DATA`: the power IRP, or why it does
/// not decode.
#[record]
pub struct PowerIrpEntry {
    /// The `_POP_IRP_DATA`.
    pub data: VirtAddr,
    #[record(rename = "power_irp")]
    pub irp: DiagnosticValue<PowerIrp>,
}

/// The power IRPs on a list of `_POP_IRP_DATA`, normally `nt!PopIrpList`.
#[record]
pub struct PowerIrpList {
    pub head: VirtAddr,
    /// The symbol of the head, such as `nt!PopIrpList`, when it is one.
    pub head_name: Option<&'static str>,
    pub entries: Vec<PowerIrpEntry>,
    /// Why the walk stopped short of the head.
    pub stopped: Option<String>,
}

/// A thread that passes power IRPs to drivers (`_POP_IRP_WORKER_ENTRY`).
#[record]
pub struct PowerWorker {
    pub thread: VirtAddr,
    /// The IRP it is passing to a driver, or 0 while it waits for work.
    pub irp: VirtAddr,
    pub device: VirtAddr,
    pub driver: Option<String>,
    /// The power manager keeps the thread when it runs out of work.
    pub is_static: bool,
}

/// An entry on a list of `_POP_IRP_WORKER_ENTRY`: the worker, or why it
/// does not decode.
#[record]
pub struct PowerWorkerEntry {
    pub entry: VirtAddr,
    pub worker: DiagnosticValue<PowerWorker>,
}

/// The IRP worker threads on a list, normally `nt!PopIrpThreadList`.
#[record]
pub struct PowerWorkerList {
    pub head: VirtAddr,
    pub head_name: Option<&'static str>,
    pub entries: Vec<PowerWorkerEntry>,
    pub stopped: Option<String>,
}

/// The device notification pass of a system power action
/// (`_POP_DEVICE_SYS_STATE`, `PopAction.DevState`).
#[record]
pub struct DeviceNotifyState {
    pub address: VirtAddr,
    #[record(hex)]
    pub irp_minor: u8,
    pub system_state: PowerEnum,
    pub thread: VirtAddr,
    #[record(hex)]
    pub status: u32,
    pub failed_device: VirtAddr,
    pub waking: bool,
    pub cancelled: bool,
}

/// The system power action (`nt!PopAction`).
#[record(impl)]
pub struct PowerAction {
    pub address: VirtAddr,
    pub updates: u8,
    pub state: u8,
    pub shutdown: bool,
    pub action: PowerEnum,
    pub lightest_state: PowerEnum,
    pub flags: u32,
    pub status: u32,
    pub irp_minor: u8,
    pub waking: bool,
    /// The system state being entered.
    pub system_state: PowerEnum,
    pub next_system_state: PowerEnum,
    pub effective_system_state: PowerEnum,
    pub current_system_state: PowerEnum,
    pub hiber_context: VirtAddr,
    pub action_worker_thread: VirtAddr,
    /// The device notification pass in progress, when there is one.
    pub devices: Option<DiagnosticValue<DeviceNotifyState>>,
}

#[record]
impl PowerAction {
    /// `Idle`, `NewRequest`, `Callout`, or `SetSystemState`.
    #[record(getter)]
    pub fn state_name(&self) -> Option<&'static str> {
        power_action_state_name(self.state)
    }

    /// The `POWER_ACTION_*` flags, such as `QUERY_ALLOWED`.
    #[record(getter)]
    pub fn flag_names(&self) -> Vec<&'static str> {
        power_action_flag_names(self.flags)
    }
}

/// `!poaction`: the power action, the power IRPs, and the IRP worker
/// threads.
#[record]
pub struct PowerActionDetail {
    #[record(rename = "record")]
    pub action: PowerAction,
    /// The power IRPs on `nt!PopIrpList`.
    pub irps: DiagnosticValue<PowerIrpList>,
    /// The IRP worker threads on `nt!PopIrpThreadList`.
    pub workers: DiagnosticValue<PowerWorkerList>,
}

/// The idle detection a driver registered with
/// `PoRegisterDeviceForIdleDetection` (`_DEVICE_OBJECT_POWER_EXTENSION`).
#[record]
pub struct IdleDetection {
    pub address: VirtAddr,
    pub idle_count: u32,
    pub busy_count: u32,
    pub busy_reference: u32,
    pub total_busy_count: u32,
    /// Seconds idle before the power manager powers the device down, on
    /// battery and on AC power.
    pub conservation_idle_time: u32,
    pub performance_idle_time: u32,
    pub idle_type: PowerEnum,
    /// The device state the power manager requests when the device idles.
    pub idle_state: PowerEnum,
    pub current_state: PowerEnum,
}

/// The power fields of the device node of a device's stack.
#[record]
pub struct DevNodePower {
    pub address: VirtAddr,
    pub instance_path: String,
    /// `CurrentPowerState`: the device state the PDO is in, as PnP records
    /// it.
    pub current_state: PowerEnum,
    /// The device's runtime power management (`_POP_FX_DEVICE`), or 0 when
    /// its driver did not register with the power framework.
    pub fx_device: VirtAddr,
    /// The device power IRP the power framework has outstanding.
    pub fx_pending_irp: Option<VirtAddr>,
}

/// `!podev`: a device object's power state.
#[record(impl)]
pub struct DevicePower {
    pub device: VirtAddr,
    pub driver: DiagnosticValue<DeviceDriver>,
    /// `DEVICE_OBJECT.Flags`, for `DO_POWER_PAGABLE` and `DO_POWER_INRUSH`.
    pub flags: u32,
    pub extension: VirtAddr,
    pub power_flags: u32,
    /// The last system state the driver set with `PoSetPowerState`.
    pub system_state: PowerEnum,
    /// The last device state the driver set with `PoSetPowerState`.
    pub device_state: PowerEnum,
    pub idle: Option<DiagnosticValue<IdleDetection>>,
    pub devnode: Option<DiagnosticValue<DevNodePower>>,
    /// The power IRPs on `nt!PopIrpList` sent to the device's stack.
    pub irps: DiagnosticValue<Vec<PowerIrp>>,
}

#[record]
impl DevicePower {
    /// `DO_POWER_PAGABLE`: the driver handles power IRPs at PASSIVE_LEVEL.
    #[record(getter)]
    pub fn power_pagable(&self) -> bool {
        self.flags & DO_POWER_PAGABLE != 0
    }

    /// `DO_POWER_INRUSH`: the device draws inrush current at power-up.
    #[record(getter)]
    pub fn power_inrush(&self) -> bool {
        self.flags & DO_POWER_INRUSH != 0
    }
}

/// A `POWER_ACTION_POLICY`: what the system does for an event.
#[derive(Debug, Clone)]
pub struct ActionPolicy {
    pub action: PowerEnum,
    pub flags: u32,
    pub event_code: u32,
}

/// One battery discharge level of a power policy (`SYSTEM_POWER_LEVEL`).
#[derive(Debug, Clone)]
pub struct DischargeLevel {
    pub enabled: bool,
    pub battery_level: u32,
    pub policy: ActionPolicy,
    pub min_system_state: PowerEnum,
}

/// `!popolicy`: the system power policy in effect (`SYSTEM_POWER_POLICY` at
/// `nt!PopPolicy`).
#[derive(Debug, Clone)]
pub struct PowerPolicy {
    pub address: VirtAddr,
    pub revision: u32,
    /// The action policies, each with its field name (`PowerButton`).
    pub actions: Vec<(&'static str, ActionPolicy)>,
    pub lid_open_wake: PowerEnum,
    pub idle_timeout: u32,
    pub idle_sensitivity: u8,
    pub dynamic_throttle: u8,
    pub min_sleep: PowerEnum,
    pub max_sleep: PowerEnum,
    pub reduced_latency_sleep: PowerEnum,
    pub win_logon_flags: u32,
    pub doze_s4_timeout: u32,
    pub broadcast_capacity_resolution: u32,
    pub discharge: Vec<DischargeLevel>,
    pub video_timeout: u32,
    pub video_dim_display: bool,
    pub spindown_timeout: u32,
    pub optimize_for_power: bool,
    pub fan_throttle_tolerance: u8,
    pub forced_throttle: u8,
    pub min_throttle: u8,
}

/// The driver a DRIVER_POWER_STATE_FAILURE names, and why.
#[record]
#[derive(Debug, Clone)]
pub struct PowerCulprit {
    pub driver: DeviceDriver,
    /// The device object that ties the driver to the failure.
    pub device: VirtAddr,
    pub reason: String,
}

/// The IRP of a 0x9F/0x3: where it is pending, and its `_POP_IRP_DATA`.
#[record]
#[derive(Debug, Clone)]
pub struct BlockedIrp {
    pub irp: VirtAddr,
    /// The driver of the IRP's current stack location.
    pub holder: DiagnosticValue<IrpHolder>,
    /// The IRP's entry on the power IRP list, when it is there.
    #[record(rename = "power_irp")]
    pub data: Option<PowerIrp>,
}

/// What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck, by subtype
/// (parameter 1).
#[record(impl)]
#[derive(Debug, Clone)]
pub struct PowerFailure {
    /// Parameter 1.
    #[record(hex)]
    pub subtype: u64,
    pub description: &'static str,
    /// The device object the parameters name: the PDO for 0x3 and 0x5, the
    /// device for 0x1, 0x2, and 0x500.
    pub device: Option<VirtAddr>,
    /// The stack of `device`, or why it is unknown (see the `device_stack`
    /// property).
    #[record(skip)]
    pub stack: Option<std::result::Result<DeviceStackDetail, String>>,
    /// 0x3: the blocked IRP.
    pub blocked_irp: Option<BlockedIrp>,
    /// 0x3: the power IRPs, from the list `TRIAGE_9F_POWER` names.
    pub irps: Option<PowerIrpList>,
    /// 0x3: the IRP worker threads, from the list `TRIAGE_9F_POWER` names.
    pub workers: Option<PowerWorkerList>,
    /// 0x4: the thread that holds the PnP lock.
    pub pnp_lock_owner: Option<VirtAddr>,
    /// 0x4: the timeout, in seconds.
    pub timeout_seconds: Option<u64>,
    pub culprit: Option<PowerCulprit>,
    /// What could not be read, and why.
    pub notes: Vec<String>,
}

#[record]
impl PowerFailure {
    /// The stack of `device`, or why it is unknown.
    #[record(getter)]
    pub fn device_stack(&self) -> Option<DiagnosticValue<DeviceStackDetail>> {
        self.stack.as_ref().map(|stack| match stack {
            Ok(stack) => DiagnosticValue::Available(stack.clone()),
            Err(error) => DiagnosticValue::unavailable(error.clone()),
        })
    }
}

/// What a 0x9F subtype means, for the subtypes Microsoft documents.
pub fn power_failure_description(subtype: u64) -> Option<&'static str> {
    match subtype {
        0x1 => Some("a device object was freed with a power request outstanding"),
        0x2 => Some("a driver completed a power IRP without calling PoStartNextPowerIrp"),
        0x3 => Some("a device blocked a power IRP for too long"),
        0x4 => Some("a power transition timed out waiting to synchronize with PnP"),
        0x5 => Some("a directed power transition timed out"),
        0x6 => Some("a directed power transition callback failed"),
        0x500 => Some("a driver completed a power IRP without calling PoStartNextPowerIrp"),
        _ => None,
    }
}

/// The lists a 0x9F/0x3 walks when its `TRIAGE_9F_POWER` does not name
/// them: `nt!PopIrpList` and `nt!PopIrpThreadList`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerListHeads {
    pub irps: Option<VirtAddr>,
    pub workers: Option<VirtAddr>,
}

/// The enum names the readers label values with.
#[derive(Default)]
struct PowerNames {
    system: Vec<(String, i64)>,
    device: Vec<(String, i64)>,
    action: Vec<(String, i64)>,
    watchdog: Vec<(String, i64)>,
    idle_type: Vec<(String, i64)>,
}

fn power_enum(variants: &[(String, i64)], prefix: &str, value: u64) -> PowerEnum {
    let name = variants
        .iter()
        .find(|(_, v)| *v as u64 == value)
        .map(|(name, _)| {
            name.strip_prefix(prefix)
                .filter(|rest| !rest.is_empty())
                .unwrap_or(name)
                .to_string()
        });
    PowerEnum { value, name }
}

/// Reads power structures in one type namespace and address space.
pub struct PowerReader<'a> {
    target: &'a Target,
    types: Types<'a>,
    names: PowerNames,
    /// The unbiased interrupt time now, which `WatchdogStart` counts in.
    now: Option<u64>,
    modules: OnceCell<Vec<ModuleInfo>>,
}

impl<'a> PowerReader<'a> {
    pub fn new(target: &'a Target, types: Types<'a>, now: Option<u64>) -> Self {
        let variants = |name: &str| {
            target
                .symbols
                .find_enum_across_modules(target.kernel_dtb(), &format!("nt!{name}"))
                .unwrap_or_default()
        };
        Self {
            names: PowerNames {
                system: variants("_SYSTEM_POWER_STATE"),
                device: variants("_DEVICE_POWER_STATE"),
                action: variants("POWER_ACTION"),
                watchdog: variants("_POP_IRP_WATCHDOG_STATE"),
                idle_type: variants("_POP_DEVICE_IDLE_TYPE"),
            },
            target,
            types,
            now,
            modules: OnceCell::new(),
        }
    }

    fn system_state(&self, value: u64) -> PowerEnum {
        power_enum(&self.names.system, "PowerSystem", value)
    }

    fn device_state(&self, value: u64) -> PowerEnum {
        power_enum(&self.names.device, "PowerDevice", value)
    }

    fn action(&self, value: u64) -> PowerEnum {
        power_enum(&self.names.action, "PowerAction", value)
    }

    fn power_state(&self, kind: u64, value: u64) -> PowerState {
        if kind == DEVICE_POWER_STATE {
            PowerState::Device(self.device_state(value))
        } else {
            PowerState::System(self.system_state(value))
        }
    }

    fn modules(&self) -> &[ModuleInfo] {
        self.modules
            .get_or_init(|| self.target.kernel_modules().unwrap_or_default())
    }

    /// The driver of the device object at `device`.
    fn device_driver(&self, device: VirtAddr) -> Result<DeviceDriver> {
        let object = self.types.struct_at("_DEVICE_OBJECT", device)?;
        let kind = object.read_uint("Type")?;
        if kind != IO_TYPE_DEVICE {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not a device object (Type {kind:#x})",
                device.0
            )));
        }
        self.driver(object.read_pointer("DriverObject")?)
    }

    fn driver(&self, driver_object: VirtAddr) -> Result<DeviceDriver> {
        let driver = self.types.struct_at("_DRIVER_OBJECT", driver_object)?;
        let kind = driver.read_uint("Type")?;
        if kind != IO_TYPE_DRIVER {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not a driver object (Type {kind:#x})",
                driver_object.0
            )));
        }
        let driver_start = driver.read_pointer("DriverStart")?;
        let module = self
            .modules()
            .iter()
            .find(|module| module.contains_address(driver_start))
            .map(|module| module_filename(&module.name).to_string());
        Ok(DeviceDriver {
            driver_object,
            name: driver.unicode_string("DriverName").unwrap_or_default(),
            driver_start,
            module,
        })
    }

    /// The driver name of `device` for a listing; `None` for 0 or an
    /// unreadable device.
    fn driver_label(&self, device: VirtAddr) -> Option<String> {
        if device.is_zero() {
            return None;
        }
        self.device_driver(device).ok().map(|driver| driver.label())
    }

    /// Where the IRP at `irp` is pending.
    fn irp_holder(&self, irp: VirtAddr) -> Result<IrpHolder> {
        let info = self.target.irp_info(&self.types.struct_at("_IRP", irp)?)?;
        self.holder_of(&info)
    }

    fn holder_of(&self, info: &IrpInfo) -> Result<IrpHolder> {
        if u64::from(info.irp_type) != IO_TYPE_IRP {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not an IRP (Type {:#x})",
                info.address.0, info.irp_type
            )));
        }
        let location = info.current_stack().ok_or_else(|| {
            Error::DebugInfo(format!(
                "the IRP is in no driver: CurrentLocation is {} of {}",
                info.current_location, info.stack_count
            ))
        })?;
        if location.device_object.is_zero() {
            return Err(Error::DebugInfo(format!(
                "stack location {} names no device",
                info.current_location
            )));
        }
        let state = (location.major_function == IRP_MJ_POWER)
            .then(|| self.location_power_state(location.address, location.minor_function))
            .flatten();
        Ok(IrpHolder {
            location: info.current_location,
            stack_count: info.stack_count,
            stack_location: location.address,
            major_function: location.major_function,
            minor_function: location.minor_function,
            state,
            pending_returned: location.control & SL_PENDING_RETURNED != 0,
            device: location.device_object,
            driver: DiagnosticValue::from_result(self.device_driver(location.device_object)),
        })
    }

    /// The state a power request in the stack location at `address` asks
    /// for: `Parameters.WaitWake` for a wait/wake IRP, `Parameters.Power`
    /// for a set or query.
    fn location_power_state(&self, address: VirtAddr, minor: u8) -> Option<PowerState> {
        let parameters = self
            .types
            .struct_at("_IO_STACK_LOCATION", address)
            .and_then(|location| location.embedded("Parameters"))
            .ok()?;
        match minor {
            IRP_MN_WAIT_WAKE => {
                let state = parameters
                    .embedded("WaitWake")
                    .and_then(|wake| wake.read_uint("PowerState"))
                    .ok()?;
                Some(PowerState::System(self.system_state(state)))
            }
            IRP_MN_SET_POWER | IRP_MN_QUERY_POWER => {
                let power = parameters.embedded("Power").ok()?;
                let kind = power.read_uint("Type").ok()?;
                let state = power.embedded("State").ok()?;
                let value = if kind == DEVICE_POWER_STATE {
                    state.read_uint("DeviceState")
                } else {
                    state.read_uint("SystemState")
                }
                .ok()?;
                Some(self.power_state(kind, value))
            }
            _ => None,
        }
    }

    fn power_irp(&self, data: &StructRef<'_>) -> Result<PowerIrp> {
        let irp = data.read_pointer("Irp")?;
        let minor_function: u8 = data.read_field("MinorFunction")?;
        let kind = data.read_uint("PowerStateType")?;
        let power_state = data.embedded("PowerState")?;
        let value = if kind == DEVICE_POWER_STATE {
            power_state.read_uint("DeviceState")?
        } else {
            power_state.read_uint("SystemState")?
        };
        // A wait/wake IRP carries the deepest system state it can wake
        // the system from, whatever the type says.
        let state = if minor_function == IRP_MN_WAIT_WAKE {
            PowerState::System(self.system_state(value))
        } else {
            self.power_state(kind, value)
        };
        let watchdog_state = data.read_uint("WatchdogState").unwrap_or(0);
        let watchdog_start = data.read_uint("WatchdogStart").unwrap_or(0);
        let pending = (watchdog_start != 0)
            .then(|| self.now.map(|now| now.saturating_sub(watchdog_start)))
            .flatten();
        let holder = if irp.is_zero() {
            DiagnosticValue::unavailable("the entry names no IRP")
        } else {
            DiagnosticValue::from_result(self.irp_holder(irp))
        };
        Ok(PowerIrp {
            data: data.addr(),
            irp,
            pdo: data.read_pointer("Pdo")?,
            target_device: data.read_pointer("TargetDevice")?,
            current_device: data.read_pointer("CurrentDevice")?,
            minor_function,
            state,
            system_transition: data.read_field::<u8>("SystemTransition").unwrap_or(0) != 0,
            watchdog: power_enum(&self.names.watchdog, "IrpWatchdogState", watchdog_state),
            pending,
            holder,
        })
    }

    /// Walk a list of `_POP_IRP_DATA` from `head`.
    pub fn irp_list(&self, head: VirtAddr, head_name: Option<&'static str>) -> PowerIrpList {
        let (entries, stopped) = self.collect_list(head, "_POP_IRP_DATA", MAX_POWER_IRPS, |data| {
            PowerIrpEntry {
                data: data.addr(),
                irp: DiagnosticValue::from_result(self.power_irp(data)),
            }
        });
        PowerIrpList {
            head,
            head_name,
            entries,
            stopped,
        }
    }

    fn worker(&self, entry: &StructRef<'_>) -> Result<PowerWorker> {
        let device = entry.read_pointer("Device")?;
        Ok(PowerWorker {
            thread: entry.read_pointer("Thread")?,
            irp: entry.read_pointer("Irp")?,
            device,
            driver: self.driver_label(device),
            is_static: entry.read_field::<u8>("Static")? != 0,
        })
    }

    /// Walk a list of `_POP_IRP_WORKER_ENTRY` from `head`.
    pub fn worker_list(&self, head: VirtAddr, head_name: Option<&'static str>) -> PowerWorkerList {
        let (entries, stopped) =
            self.collect_list(head, "_POP_IRP_WORKER_ENTRY", MAX_IRP_WORKERS, |entry| {
                PowerWorkerEntry {
                    entry: entry.addr(),
                    worker: DiagnosticValue::from_result(self.worker(entry)),
                }
            });
        PowerWorkerList {
            head,
            head_name,
            entries,
            stopped,
        }
    }

    /// The records of the `record_type` list at `head`, linked through
    /// `Link`, each made into an entry by `entry`; at most `cap` of them. The
    /// second value says why the walk stopped short: an unresolved layout, the
    /// cap, or an unreadable link. A record that fails to decode is the
    /// entry's business and does not stop the walk.
    fn collect_list<T>(
        &self,
        head: VirtAddr,
        record_type: &str,
        cap: usize,
        entry: impl Fn(&StructRef<'a>) -> T,
    ) -> (Vec<T>, Option<String>) {
        let records = match self.types.list_at(head, record_type, "Link") {
            Ok(records) => records,
            Err(error) => return (Vec::new(), Some(error.to_string())),
        };
        let mut entries = Vec::new();
        for record in records {
            if entries.len() >= cap {
                return (entries, Some(format!("stopped after {cap} entries")));
            }
            match record {
                Ok(record) => entries.push(entry(&record)),
                Err(error) => return (entries, Some(format!("unreadable link: {error}"))),
            }
        }
        (entries, None)
    }

    fn power_action(&self, address: VirtAddr) -> Result<PowerAction> {
        let action = self
            .types
            .struct_at("_POP_POWER_ACTION", address)?
            .prefetch();
        let dev_state = action.read_pointer("DevState").unwrap_or(VirtAddr(0));
        let devices = (!dev_state.is_zero())
            .then(|| DiagnosticValue::from_result(self.device_notify_state(dev_state)));
        Ok(PowerAction {
            address,
            updates: action.read_field("Updates")?,
            state: action.read_field("State")?,
            shutdown: action.read_field::<u8>("Shutdown")? != 0,
            action: self.action(action.read_uint("Action")?),
            lightest_state: self.system_state(action.read_uint("LightestState")?),
            flags: action.read_uint("Flags")? as u32,
            status: action.read_uint("Status")? as u32,
            irp_minor: action.read_field("IrpMinor")?,
            waking: action.read_field::<u8>("Waking").unwrap_or(0) != 0,
            system_state: self.system_state(action.read_uint("SystemState")?),
            next_system_state: self.system_state(action.read_uint("NextSystemState").unwrap_or(0)),
            effective_system_state: self
                .system_state(action.read_uint("EffectiveSystemState").unwrap_or(0)),
            current_system_state: self
                .system_state(action.read_uint("CurrentSystemState").unwrap_or(0)),
            hiber_context: action.read_pointer("HiberContext").unwrap_or(VirtAddr(0)),
            action_worker_thread: action
                .read_pointer("ActionWorkerThread")
                .unwrap_or(VirtAddr(0)),
            devices,
        })
    }

    fn device_notify_state(&self, address: VirtAddr) -> Result<DeviceNotifyState> {
        let state = self.types.struct_at("_POP_DEVICE_SYS_STATE", address)?;
        Ok(DeviceNotifyState {
            address,
            irp_minor: state.read_field("IrpMinor")?,
            system_state: self.system_state(state.read_uint("SystemState")?),
            thread: state.read_pointer("Thread")?,
            status: state.read_uint("Status")? as u32,
            failed_device: state.read_pointer("FailedDevice")?,
            waking: state.read_field::<u8>("Waking")? != 0,
            cancelled: state.read_field::<u8>("Cancelled")? != 0,
        })
    }

    fn idle_detection(&self, address: VirtAddr, device: VirtAddr) -> Result<IdleDetection> {
        let dope = self
            .types
            .struct_at("_DEVICE_OBJECT_POWER_EXTENSION", address)?;
        let back = dope.read_pointer("DeviceObject")?;
        if back != device {
            return Err(Error::DebugInfo(format!(
                "its DeviceObject is {:#x}, not the device",
                back.0
            )));
        }
        let u32_field = |name| dope.read_uint(name).map(|value| value as u32);
        Ok(IdleDetection {
            address,
            idle_count: u32_field("IdleCount")?,
            busy_count: u32_field("BusyCount")?,
            busy_reference: u32_field("BusyReference")?,
            total_busy_count: u32_field("TotalBusyCount")?,
            conservation_idle_time: u32_field("ConservationIdleTime")?,
            performance_idle_time: u32_field("PerformanceIdleTime")?,
            idle_type: power_enum(
                &self.names.idle_type,
                "DeviceIdle",
                dope.read_uint("IdleType")?,
            ),
            idle_state: self.device_state(dope.read_uint("IdleState")?),
            current_state: self.device_state(dope.read_uint("CurrentState")?),
        })
    }

    fn devnode_power(&self, address: VirtAddr) -> Result<DevNodePower> {
        let node = self.types.struct_at("_DEVICE_NODE", address)?;
        let current_state = node
            .embedded("CurrentPowerState")?
            .read_uint("DeviceState")?;
        let fx_device = node.read_pointer("FxDevice").unwrap_or(VirtAddr(0));
        let fx_pending_irp = (!fx_device.is_zero())
            .then(|| {
                self.types
                    .struct_at("_POP_FX_DEVICE", fx_device)
                    .and_then(|fx| fx.read_pointer("PendingDevicePowerIrp"))
                    .ok()
            })
            .flatten();
        Ok(DevNodePower {
            address,
            instance_path: node.unicode_string("InstancePath").unwrap_or_default(),
            current_state: self.device_state(current_state),
            fx_device,
            fx_pending_irp,
        })
    }

    /// `device`'s power state; `stack` is the devices of its stack and
    /// `stack_devnode` the device node of the stack's PDO, when known.
    fn device_power(
        &self,
        device: VirtAddr,
        stack: &[VirtAddr],
        stack_devnode: Option<VirtAddr>,
        irp_list: Option<VirtAddr>,
    ) -> Result<DevicePower> {
        let object = self.types.struct_at("_DEVICE_OBJECT", device)?;
        let kind = object.read_uint("Type")?;
        if kind != IO_TYPE_DEVICE {
            return Err(Error::DebugInfo(format!(
                "{:#x} is not a device object (Type {kind:#x})",
                device.0
            )));
        }
        let flags = object.read_uint("Flags")? as u32;
        let extension_address = object.read_pointer("DeviceObjectExtension")?;
        let extension = self
            .types
            .struct_at("_DEVOBJ_EXTENSION", extension_address)?;
        let back = extension.read_pointer("DeviceObject")?;
        if back != device {
            return Err(Error::DebugInfo(format!(
                "the device extension at {:#x} belongs to {:#x}",
                extension_address.0, back.0
            )));
        }
        let power_flags = extension.read_uint("PowerFlags")? as u32;
        let dope = extension.read_pointer("Dope")?;
        let idle = (!dope.is_zero())
            .then(|| DiagnosticValue::from_result(self.idle_detection(dope, device)));
        let own_devnode = extension.read_pointer("DeviceNode").unwrap_or(VirtAddr(0));
        let devnode = Some(own_devnode)
            .filter(|node| !node.is_zero())
            .or(stack_devnode)
            .map(|node| DiagnosticValue::from_result(self.devnode_power(node)));
        let irps = match irp_list {
            None => DiagnosticValue::unavailable("nt!PopIrpList is not in the kernel's symbols"),
            Some(head) => {
                let list = self.irp_list(head, Some("nt!PopIrpList"));
                match list.stopped {
                    Some(stopped) if list.entries.is_empty() => {
                        DiagnosticValue::Unavailable(stopped)
                    }
                    _ => DiagnosticValue::Available(
                        list.entries
                            .into_iter()
                            .filter_map(|entry| match entry.irp {
                                DiagnosticValue::Available(irp) => Some(irp),
                                DiagnosticValue::Unavailable(_) => None,
                            })
                            .filter(|irp| irp_concerns(irp, device, stack))
                            .collect(),
                    ),
                }
            }
        };
        Ok(DevicePower {
            device,
            driver: DiagnosticValue::from_result(self.driver(object.read_pointer("DriverObject")?)),
            flags,
            extension: extension_address,
            power_flags,
            system_state: self.system_state(u64::from(power_flags & POWER_FLAGS_SYSTEM_STATE)),
            device_state: self
                .device_state(u64::from((power_flags & POWER_FLAGS_DEVICE_STATE) >> 4)),
            idle,
            devnode,
            irps,
        })
    }

    fn action_policy(&self, policy: &StructRef<'_>) -> Result<ActionPolicy> {
        Ok(ActionPolicy {
            action: self.action(policy.read_uint("Action")?),
            flags: policy.read_uint("Flags")? as u32,
            event_code: policy.read_uint("EventCode")? as u32,
        })
    }

    fn power_policy(&self, address: VirtAddr) -> Result<PowerPolicy> {
        let policy = self
            .types
            .struct_at("_SYSTEM_POWER_POLICY", address)?
            .prefetch();
        let u32_field = |name| policy.read_uint(name).map(|value| value as u32);
        let u8_field = |name| policy.read_uint(name).map(|value| value as u8);
        let mut actions = Vec::new();
        for name in [
            "PowerButton",
            "SleepButton",
            "LidClose",
            "Idle",
            "OverThrottled",
        ] {
            actions.push((name, self.action_policy(&policy.embedded(name)?)?));
        }
        Ok(PowerPolicy {
            address,
            revision: u32_field("Revision")?,
            actions,
            lid_open_wake: self.system_state(policy.read_uint("LidOpenWake")?),
            idle_timeout: u32_field("IdleTimeout")?,
            idle_sensitivity: u8_field("IdleSensitivity")?,
            dynamic_throttle: u8_field("DynamicThrottle")?,
            min_sleep: self.system_state(policy.read_uint("MinSleep")?),
            max_sleep: self.system_state(policy.read_uint("MaxSleep")?),
            reduced_latency_sleep: self.system_state(policy.read_uint("ReducedLatencySleep")?),
            win_logon_flags: u32_field("WinLogonFlags")?,
            doze_s4_timeout: u32_field("DozeS4Timeout")?,
            broadcast_capacity_resolution: u32_field("BroadcastCapacityResolution")?,
            discharge: self.discharge_levels(&policy)?,
            video_timeout: u32_field("VideoTimeout")?,
            video_dim_display: u8_field("VideoDimDisplay")? != 0,
            spindown_timeout: u32_field("SpindownTimeout")?,
            optimize_for_power: u8_field("OptimizeForPower")? != 0,
            fan_throttle_tolerance: u8_field("FanThrottleTolerance")?,
            forced_throttle: u8_field("ForcedThrottle")?,
            min_throttle: u8_field("MinThrottle")?,
        })
    }

    /// The `DischargePolicy` array, each element typed by the array's own
    /// element type.
    fn discharge_levels(&self, policy: &StructRef<'_>) -> Result<Vec<DischargeLevel>> {
        let field = policy.layout().field("DischargePolicy")?;
        let ParsedType::Array(element, count) = &field.type_data else {
            return Err(Error::FieldTypeMismatch(
                "DischargePolicy".into(),
                "array".into(),
            ));
        };
        let ParsedType::Struct(element) = element.as_ref() else {
            return Err(Error::FieldTypeMismatch(
                "DischargePolicy".into(),
                "array of structs".into(),
            ));
        };
        let layout = self.types.layout(element.as_str())?;
        let base = policy.addr() + u64::from(field.offset);
        (0..u64::from(*count).min(16))
            .map(|index| {
                let level = self
                    .types
                    .struct_with_layout(layout.clone(), base + index * layout.size as u64);
                Ok(DischargeLevel {
                    enabled: level.read_uint("Enable")? != 0,
                    battery_level: level.read_uint("BatteryLevel")? as u32,
                    policy: self.action_policy(&level.embedded("PowerPolicy")?)?,
                    min_system_state: self.system_state(level.read_uint("MinSystemState")?),
                })
            })
            .collect()
    }

    /// The device stack of `device`, or why it is unknown.
    fn stack(&self, device: VirtAddr) -> std::result::Result<DeviceStackDetail, String> {
        self.target
            .inspect_device_stack(device)
            .map_err(|error| error.to_string())
    }

    /// Read what a 0x9F with `parameters` names. `heads` are the power IRP
    /// and worker lists to fall back to when a 0x3's `TRIAGE_9F_POWER` does
    /// not name them.
    pub fn power_failure(&self, parameters: [u64; 4], heads: PowerListHeads) -> PowerFailure {
        let [subtype, p2, p3, p4] = parameters;
        let mut failure = PowerFailure {
            subtype,
            description: power_failure_description(subtype).unwrap_or("unknown subtype"),
            device: None,
            stack: None,
            blocked_irp: None,
            irps: None,
            workers: None,
            pnp_lock_owner: None,
            timeout_seconds: None,
            culprit: None,
            notes: Vec::new(),
        };
        let device = match subtype {
            0x1 | 0x3 | 0x5 => p2,
            0x2 => p3,
            0x500 => p4,
            _ => 0,
        };
        if device != 0 {
            failure.device = Some(VirtAddr(device));
            failure.stack = Some(self.stack(VirtAddr(device)));
        }
        match subtype {
            0x1 => self.blame_device(
                &mut failure,
                VirtAddr(device),
                "owns the device object freed with a power request outstanding",
            ),
            0x2 if p4 != 0 => match self.driver(VirtAddr(p4)) {
                Ok(driver) => {
                    failure.culprit = Some(PowerCulprit {
                        driver,
                        device: VirtAddr(p3),
                        reason: "completed a power IRP without calling PoStartNextPowerIrp"
                            .to_string(),
                    })
                }
                Err(error) => failure
                    .notes
                    .push(format!("driver object {p4:#x}: {error}")),
            },
            0x2 | 0x500 => self.blame_device(
                &mut failure,
                VirtAddr(device),
                "completed a power IRP without calling PoStartNextPowerIrp",
            ),
            0x3 => self.blocked_irp(&mut failure, VirtAddr(p3), VirtAddr(p4), heads),
            0x4 => {
                failure.timeout_seconds = Some(p2);
                failure.pnp_lock_owner = Some(VirtAddr(p3));
            }
            _ => {}
        }
        failure
    }

    fn blame_device(&self, failure: &mut PowerFailure, device: VirtAddr, reason: &str) {
        if device.is_zero() {
            return;
        }
        match self.device_driver(device) {
            Ok(driver) => {
                failure.culprit = Some(PowerCulprit {
                    driver,
                    device,
                    reason: reason.to_string(),
                })
            }
            Err(error) => failure
                .notes
                .push(format!("device object {:#x}: {error}", device.0)),
        }
    }

    /// 0x3: the blocked IRP, where it is pending, and the lists
    /// `TRIAGE_9F_POWER` names.
    fn blocked_irp(
        &self,
        failure: &mut PowerFailure,
        triage: VirtAddr,
        irp: VirtAddr,
        heads: PowerListHeads,
    ) {
        let (irp_head, worker_head) = match self.triage_9f_power(triage) {
            // A block that leaves one list out still has the kernel's.
            Ok((irps, workers)) => (irps.or(heads.irps), workers.or(heads.workers)),
            Err(error) => {
                failure.notes.push(format!(
                    "parameter 3 ({:#x}) is not a readable TRIAGE_9F_POWER: {error}; \
                     walked nt!PopIrpList and nt!PopIrpThreadList",
                    triage.0
                ));
                (heads.irps, heads.workers)
            }
        };
        // The kernel's own lists, when the triage block names them.
        let name = |head: VirtAddr, known: Option<VirtAddr>, symbol| {
            (Some(head) == known).then_some(symbol)
        };
        let irps =
            irp_head.map(|head| self.irp_list(head, name(head, heads.irps, "nt!PopIrpList")));
        let data = irps.as_ref().and_then(|list| {
            list.entries
                .iter()
                .filter_map(|entry| entry.irp.as_result().ok())
                .find(|entry| entry.irp == irp)
                .cloned()
        });
        if let Some(list) = &irps
            && data.is_none()
        {
            failure.notes.push(format!(
                "the IRP is not on the power IRP list at {:#x}",
                list.head.0
            ));
        }
        let holder = DiagnosticValue::from_result(self.irp_holder(irp));
        if let DiagnosticValue::Available(holder) = &holder {
            match holder.driver.as_result() {
                Ok(driver) => {
                    failure.culprit = Some(PowerCulprit {
                        driver: driver.clone(),
                        device: holder.device,
                        reason: format!(
                            "holds the blocked power IRP {:#x} in stack location {} of {}",
                            irp.0, holder.location, holder.stack_count
                        ),
                    })
                }
                Err(error) => failure.notes.push(format!(
                    "device object {:#x} of the IRP's stack location: {error}",
                    holder.device.0
                )),
            }
        }
        failure.blocked_irp = Some(BlockedIrp { irp, holder, data });
        failure.irps = irps;
        failure.workers = worker_head
            .map(|head| self.worker_list(head, name(head, heads.workers, "nt!PopIrpThreadList")));
    }

    /// The power IRP and worker list heads a `TRIAGE_9F_POWER` names.
    fn triage_9f_power(&self, address: VirtAddr) -> Result<(Option<VirtAddr>, Option<VirtAddr>)> {
        let triage = self.types.struct_at("_TRIAGE_9F_POWER", address)?;
        let signature = triage.read_uint("Signature")?;
        if signature != TRIAGE_9F_POWER_SIGNATURE {
            return Err(Error::DebugInfo(format!(
                "its signature is {signature:#x}, not {TRIAGE_9F_POWER_SIGNATURE:#x}"
            )));
        }
        let head = |name| {
            triage
                .read_pointer(name)
                .ok()
                .filter(|head| !head.is_zero())
        };
        Ok((head("IrpList"), head("ThreadList")))
    }
}

/// Whether a power IRP was sent to `device` or its stack, or is pending in
/// one of them.
fn irp_concerns(irp: &PowerIrp, device: VirtAddr, stack: &[VirtAddr]) -> bool {
    let holder = match &irp.holder {
        DiagnosticValue::Available(holder) => Some(holder.device),
        DiagnosticValue::Unavailable(_) => None,
    };
    [
        Some(irp.pdo),
        Some(irp.target_device),
        Some(irp.current_device),
        holder,
    ]
    .into_iter()
    .flatten()
    .any(|candidate| !candidate.is_zero() && (candidate == device || stack.contains(&candidate)))
}

impl Target {
    fn power_reader(&self) -> Result<PowerReader<'_>> {
        let types = self.guest()?.ntoskrnl.types();
        let now = KuserSharedData::new(self).unbiased_interrupt_time();
        Ok(PowerReader::new(self, types, now))
    }

    fn kernel_symbol_address(&self, name: &str) -> Result<VirtAddr> {
        Ok(self.guest()?.ntoskrnl.symbol(name)?.address())
    }

    /// The system power action (`nt!PopAction`), the power IRPs on
    /// `nt!PopIrpList`, and the IRP worker threads on `nt!PopIrpThreadList`
    /// (`!poaction`).
    pub fn power_action(&self) -> Result<PowerActionDetail> {
        let reader = self.power_reader()?;
        let action = reader.power_action(self.kernel_symbol_address("PopAction")?)?;
        let irps = DiagnosticValue::from_result(
            self.kernel_symbol_address("PopIrpList")
                .map(|head| reader.irp_list(head, Some("nt!PopIrpList"))),
        );
        let workers = DiagnosticValue::from_result(
            self.kernel_symbol_address("PopIrpThreadList")
                .map(|head| reader.worker_list(head, Some("nt!PopIrpThreadList"))),
        );
        Ok(PowerActionDetail {
            action,
            irps,
            workers,
        })
    }

    /// A device object's power state and the power IRPs sent to its stack
    /// (`!podev`).
    pub fn device_power(&self, device: VirtAddr) -> Result<DevicePower> {
        let reader = self.power_reader()?;
        let device = self
            .inspect_device_object(device)
            .map(|detail| detail.object)
            .unwrap_or(device);
        let stack = self.inspect_device_stack(device).ok();
        let stack_devices: Vec<VirtAddr> = stack
            .iter()
            .flat_map(|stack| stack.entries.iter().map(|entry| entry.device_object))
            .collect();
        let stack_devnode = stack
            .as_ref()
            .and_then(|stack| stack.pdo_devnode.as_ref())
            .map(|node| node.address);
        reader.device_power(
            device,
            &stack_devices,
            stack_devnode,
            self.kernel_symbol_address("PopIrpList").ok(),
        )
    }

    /// The `SYSTEM_POWER_POLICY` at `address`, by default the policy in
    /// effect, which `nt!PopPolicy` points to (`!popolicy`).
    pub fn power_policy(&self, address: Option<VirtAddr>) -> Result<PowerPolicy> {
        let reader = self.power_reader()?;
        let address = match address {
            Some(address) => address,
            None => self.guest()?.ntoskrnl.symbol("PopPolicy")?.read_pointer()?,
        };
        if address.is_zero() {
            return Err(Error::DebugInfo("the policy address is null".to_string()));
        }
        reader.power_policy(address)
    }

    /// What a DRIVER_POWER_STATE_FAILURE with `parameters` names as stuck.
    pub fn power_failure(&self, parameters: [u64; 4]) -> PowerFailure {
        match self.power_reader() {
            Ok(reader) => {
                let heads = PowerListHeads {
                    irps: self.kernel_symbol_address("PopIrpList").ok(),
                    workers: self.kernel_symbol_address("PopIrpThreadList").ok(),
                };
                reader.power_failure(parameters, heads)
            }
            Err(error) => PowerFailure {
                subtype: parameters[0],
                description: power_failure_description(parameters[0]).unwrap_or("unknown subtype"),
                device: None,
                stack: None,
                blocked_irp: None,
                irps: None,
                workers: None,
                pnp_lock_owner: (parameters[0] == 0x4).then_some(VirtAddr(parameters[2])),
                timeout_seconds: (parameters[0] == 0x4).then_some(parameters[1]),
                culprit: None,
                notes: vec![format!("kernel structures are unreadable: {error}")],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt::layout::{FieldInfo, TypeInfo};
    use crate::session::{Session, session_over_memory};

    const BASE: u64 = 0x1000;
    const TRIAGE: u64 = BASE;
    const IRP_HEAD: u64 = BASE + 0x40;
    const WORKER_HEAD: u64 = BASE + 0x60;
    const IRP_DATA: u64 = BASE + 0x100;
    const WORKER: u64 = BASE + 0x300;
    const IRP: u64 = BASE + 0x400;
    /// `_IRP` is 0xd0 bytes here; its stack locations, 0x48 each, follow.
    const STACK: u64 = IRP + 0xd0;
    const HOLDER_DEVICE: u64 = BASE + 0x700;
    const FILTER_DEVICE: u64 = BASE + 0x780;
    const PDO: u64 = BASE + 0x800;
    const DRIVER: u64 = BASE + 0x900;
    const DRIVER_NAME: u64 = BASE + 0xa00;
    const MODULE_BASE: u64 = 0xffff_f800_1000_0000;
    const WATCHDOG_START: u64 = 1_000_000_000;
    const NOW: u64 = 2_200_000_000;

    fn field(offset: u32, size: u64, type_data: ParsedType) -> FieldInfo {
        FieldInfo {
            offset,
            size,
            type_data,
        }
    }

    fn scalar(offset: u32, size: u64) -> FieldInfo {
        field(
            offset,
            size,
            ParsedType::Primitive(format!("u{}", size * 8)),
        )
    }

    fn pointer(offset: u32) -> FieldInfo {
        field(
            offset,
            8,
            ParsedType::Pointer(Box::new(ParsedType::Primitive("void".into()))),
        )
    }

    fn nested(offset: u32, size: u64, name: &str) -> FieldInfo {
        field(offset, size, ParsedType::Struct(name.into()))
    }

    fn layout(name: &str, size: usize, fields: Vec<(&str, FieldInfo)>) -> TypeInfo {
        TypeInfo {
            name: name.into(),
            size,
            fields: fields
                .into_iter()
                .map(|(name, field)| (name.to_string(), field))
                .collect(),
            pointer_size: 8,
        }
    }

    /// The kernel layouts a 0x9F/0x3 reads, at offsets of their own: the
    /// reader finds every field by name.
    fn layouts() -> Vec<TypeInfo> {
        vec![
            layout(
                "_TRIAGE_9F_POWER",
                0x28,
                vec![
                    ("Signature", scalar(0, 2)),
                    ("Revision", scalar(2, 2)),
                    ("IrpList", pointer(8)),
                    ("ThreadList", pointer(0x10)),
                ],
            ),
            layout(
                "_POP_IRP_DATA",
                0x138,
                vec![
                    ("Link", nested(0, 0x10, "_LIST_ENTRY")),
                    ("Irp", pointer(0x10)),
                    ("Pdo", pointer(0x18)),
                    ("TargetDevice", pointer(0x20)),
                    ("CurrentDevice", pointer(0x28)),
                    ("WatchdogStart", scalar(0x30, 8)),
                    ("MinorFunction", scalar(0xb8, 1)),
                    ("PowerStateType", scalar(0xbc, 4)),
                    (
                        "PowerState",
                        field(0xc0, 4, ParsedType::Union("_POWER_STATE".into())),
                    ),
                    ("SystemTransition", scalar(0xd0, 1)),
                    ("WatchdogState", scalar(0x128, 4)),
                ],
            ),
            layout(
                "_POWER_STATE",
                4,
                vec![("DeviceState", scalar(0, 4)), ("SystemState", scalar(0, 4))],
            ),
            layout(
                "_POP_IRP_WORKER_ENTRY",
                0x30,
                vec![
                    ("Link", nested(0, 0x10, "_LIST_ENTRY")),
                    ("Thread", pointer(0x10)),
                    ("Irp", pointer(0x18)),
                    ("Device", pointer(0x20)),
                    ("Static", scalar(0x28, 1)),
                ],
            ),
            layout(
                "_IRP",
                0xd0,
                vec![
                    ("Type", scalar(0, 2)),
                    ("Size", scalar(2, 2)),
                    ("MdlAddress", pointer(8)),
                    ("RequestorMode", scalar(0x40, 1)),
                    ("PendingReturned", scalar(0x41, 1)),
                    ("StackCount", scalar(0x42, 1)),
                    ("CurrentLocation", scalar(0x43, 1)),
                    ("UserEvent", pointer(0x48)),
                    ("UserBuffer", pointer(0x70)),
                ],
            ),
            layout(
                "_IO_STACK_LOCATION",
                0x48,
                vec![
                    ("MajorFunction", scalar(0, 1)),
                    ("MinorFunction", scalar(1, 1)),
                    ("Flags", scalar(2, 1)),
                    ("Control", scalar(3, 1)),
                    (
                        "Parameters",
                        field(8, 0x20, ParsedType::Union("_PARAMETERS".into())),
                    ),
                    ("DeviceObject", pointer(0x28)),
                    ("FileObject", pointer(0x30)),
                    ("CompletionRoutine", pointer(0x38)),
                    ("Context", pointer(0x40)),
                ],
            ),
            layout(
                "_PARAMETERS",
                0x20,
                vec![
                    ("Others", nested(0, 0x20, "_PARAMETERS_OTHERS")),
                    ("Power", nested(0, 0x20, "_PARAMETERS_POWER")),
                    ("WaitWake", nested(0, 4, "_PARAMETERS_WAIT_WAKE")),
                ],
            ),
            layout(
                "_PARAMETERS_OTHERS",
                0x20,
                vec![
                    ("Argument1", pointer(0)),
                    ("Argument2", pointer(8)),
                    ("Argument3", pointer(0x10)),
                    ("Argument4", pointer(0x18)),
                ],
            ),
            layout(
                "_PARAMETERS_POWER",
                0x20,
                vec![
                    ("SystemContext", scalar(0, 4)),
                    ("Type", scalar(8, 4)),
                    (
                        "State",
                        field(0x10, 4, ParsedType::Union("_POWER_STATE".into())),
                    ),
                    ("ShutdownType", scalar(0x18, 4)),
                ],
            ),
            layout(
                "_PARAMETERS_WAIT_WAKE",
                4,
                vec![("PowerState", scalar(0, 4))],
            ),
            layout(
                "_DEVICE_OBJECT",
                0x150,
                vec![("Type", scalar(0, 2)), ("DriverObject", pointer(8))],
            ),
            layout(
                "_DRIVER_OBJECT",
                0x150,
                vec![
                    ("Type", scalar(0, 2)),
                    ("DriverStart", pointer(0x18)),
                    ("DriverName", nested(0x38, 0x10, "_UNICODE_STRING")),
                ],
            ),
            layout(
                "_UNICODE_STRING",
                0x10,
                vec![
                    ("Length", scalar(0, 2)),
                    ("MaximumLength", scalar(2, 2)),
                    ("Buffer", pointer(8)),
                ],
            ),
        ]
    }

    fn put(memory: &mut [u8], address: u64, bytes: &[u8]) {
        let start = (address - BASE) as usize;
        memory[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u64(memory: &mut [u8], address: u64, value: u64) {
        put(memory, address, &value.to_le_bytes());
    }

    /// A device that blocked a set-power IRP for D3: the IRP went from a
    /// filter (location 3) down to the holder's device (location 2), which
    /// returned STATUS_PENDING; one dynamic worker thread is passing it.
    fn blocked_irp_memory(signature: u16, current_location: u8) -> Vec<u8> {
        let mut memory = vec![0u8; 0xc00];
        put(&mut memory, TRIAGE, &signature.to_le_bytes());
        put(&mut memory, TRIAGE + 2, &2u16.to_le_bytes());
        put_u64(&mut memory, TRIAGE + 8, IRP_HEAD);
        put_u64(&mut memory, TRIAGE + 0x10, WORKER_HEAD);

        put_u64(&mut memory, IRP_HEAD, IRP_DATA);
        put_u64(&mut memory, IRP_HEAD + 8, IRP_DATA);
        put_u64(&mut memory, IRP_DATA, IRP_HEAD);
        put_u64(&mut memory, IRP_DATA + 8, IRP_HEAD);
        put_u64(&mut memory, IRP_DATA + 0x10, IRP);
        put_u64(&mut memory, IRP_DATA + 0x18, PDO);
        put_u64(&mut memory, IRP_DATA + 0x20, FILTER_DEVICE);
        put_u64(&mut memory, IRP_DATA + 0x30, WATCHDOG_START);
        put(&mut memory, IRP_DATA + 0xb8, &[IRP_MN_SET_POWER]);
        put(&mut memory, IRP_DATA + 0xbc, &1u32.to_le_bytes());
        put(&mut memory, IRP_DATA + 0xc0, &4u32.to_le_bytes());
        put(&mut memory, IRP_DATA + 0x128, &1u32.to_le_bytes());

        put_u64(&mut memory, WORKER_HEAD, WORKER);
        put_u64(&mut memory, WORKER_HEAD + 8, WORKER);
        put_u64(&mut memory, WORKER, WORKER_HEAD);
        put_u64(&mut memory, WORKER + 8, WORKER_HEAD);
        put_u64(&mut memory, WORKER + 0x10, 0xffff_9000_0000_1000);
        put_u64(&mut memory, WORKER + 0x18, IRP);
        put_u64(&mut memory, WORKER + 0x20, HOLDER_DEVICE);

        put(&mut memory, IRP, &(IO_TYPE_IRP as u16).to_le_bytes());
        put(&mut memory, IRP + 0x42, &[3, current_location]);
        for (location, device) in [(2u64, HOLDER_DEVICE), (3, FILTER_DEVICE)] {
            let address = STACK + (location - 1) * 0x48;
            put(&mut memory, address, &[IRP_MJ_POWER, IRP_MN_SET_POWER]);
            put(&mut memory, address + 8 + 8, &1u32.to_le_bytes());
            put(&mut memory, address + 8 + 0x10, &4u32.to_le_bytes());
            put_u64(&mut memory, address + 0x28, device);
        }
        put(&mut memory, STACK + 0x48 + 3, &[SL_PENDING_RETURNED]);

        for device in [HOLDER_DEVICE, FILTER_DEVICE, PDO] {
            put(&mut memory, device, &(IO_TYPE_DEVICE as u16).to_le_bytes());
        }
        put_u64(&mut memory, HOLDER_DEVICE + 8, DRIVER);
        put(&mut memory, DRIVER, &(IO_TYPE_DRIVER as u16).to_le_bytes());
        put_u64(&mut memory, DRIVER + 0x18, MODULE_BASE + 0x1000);
        let name: Vec<u8> = "\\Driver\\stuck"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        put(
            &mut memory,
            DRIVER + 0x38,
            &(name.len() as u16).to_le_bytes(),
        );
        put(
            &mut memory,
            DRIVER + 0x3a,
            &(name.len() as u16).to_le_bytes(),
        );
        put_u64(&mut memory, DRIVER + 0x40, DRIVER_NAME);
        put(&mut memory, DRIVER_NAME, &name);
        memory
    }

    fn session(memory: &[u8]) -> Session {
        let mut session = session_over_memory(BASE, memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, layouts(), &[]);
        session
            .target
            .set_kernel_modules_for_test(vec![ModuleInfo::new(
                "stuck.sys".into(),
                VirtAddr(MODULE_BASE),
                0x10000,
            )]);
        session
    }

    fn failure(session: &Session, parameters: [u64; 4]) -> PowerFailure {
        let target = &session.target;
        let types = Types::new(
            &target.symbols,
            Some(1),
            &target.phys,
            target.arch(),
            target.kernel_dtb(),
            target.current_dtb(),
        );
        PowerReader::new(target, types, Some(NOW)).power_failure(
            parameters,
            PowerListHeads {
                irps: Some(VirtAddr(IRP_HEAD)),
                workers: Some(VirtAddr(WORKER_HEAD)),
            },
        )
    }

    #[test]
    fn a_blocked_power_irp_is_pinned_on_the_driver_of_its_current_location() {
        let session = session(&blocked_irp_memory(0x8000, 2));
        let failure = failure(&session, [3, PDO, TRIAGE, IRP]);

        let culprit = failure.culprit.expect("a culprit");
        assert_eq!(culprit.driver.module.as_deref(), Some("stuck.sys"));
        assert_eq!(culprit.driver.name, "\\Driver\\stuck");
        assert_eq!(culprit.device, VirtAddr(HOLDER_DEVICE));
        assert!(culprit.reason.contains("stack location 2 of 3"));

        let blocked = failure.blocked_irp.expect("the blocked IRP");
        let holder = blocked.holder.as_result().expect("where it is pending");
        assert_eq!(holder.location, 2);
        assert_eq!(holder.device, VirtAddr(HOLDER_DEVICE));
        assert!(holder.pending_returned);
        assert_eq!(
            holder.state,
            Some(PowerState::Device(PowerEnum {
                value: 4,
                name: None
            }))
        );
        let data = blocked.data.expect("its POP_IRP_DATA");
        assert_eq!(data.data, VirtAddr(IRP_DATA));
        assert_eq!(data.pending, Some(NOW - WATCHDOG_START));

        // The triage block names the kernel's own lists.
        let irps = failure.irps.expect("the IRP list");
        assert_eq!(irps.head_name, Some("nt!PopIrpList"));
        assert_eq!(irps.stopped, None);
        let workers = failure.workers.expect("the worker list");
        assert_eq!(workers.head_name, Some("nt!PopIrpThreadList"));
        let [entry] = workers.entries.as_slice() else {
            panic!("one worker: {:?}", workers.entries);
        };
        let worker = entry.worker.as_result().unwrap();
        assert_eq!(worker.irp, VirtAddr(IRP));
        assert_eq!(
            worker.driver.as_deref(),
            Some("\\Driver\\stuck (stuck.sys)")
        );
        assert!(!worker.is_static);
        assert!(failure.notes.is_empty(), "{:?}", failure.notes);
    }

    #[test]
    fn without_its_triage_block_a_blocked_irp_is_found_on_the_kernel_lists() {
        let mut memory = blocked_irp_memory(0, 4);
        // A second entry whose link cannot be read ends the walk after the
        // first.
        put_u64(&mut memory, IRP_DATA, 0xdead_0000);
        let session = session(&memory);
        let failure = failure(&session, [3, PDO, TRIAGE, IRP]);

        let [note] = failure.notes.as_slice() else {
            panic!("one note: {:?}", failure.notes);
        };
        assert!(note.contains("not a readable TRIAGE_9F_POWER"), "{note}");
        let irps = failure.irps.expect("the kernel's IRP list");
        assert_eq!(irps.head, VirtAddr(IRP_HEAD));
        assert_eq!(irps.entries.len(), 1);
        assert!(
            irps.stopped
                .is_some_and(|stopped| stopped.contains("unreadable link"))
        );

        // CurrentLocation past StackCount: the IRP is in no driver, so no
        // driver is blamed.
        let blocked = failure.blocked_irp.expect("the blocked IRP");
        assert!(blocked.holder.as_result().is_err());
        assert!(blocked.data.is_some());
        assert!(failure.culprit.is_none());
    }
}
