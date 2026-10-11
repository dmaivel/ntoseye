//! Power management [`View`] builders: the power action and power IRPs
//! (`!poaction`) and a device's power state (`!podev`).

use super::shape::{Diag, Hex, shapes};
use crate::target::DiagnosticValue;
use crate::target::power::{
    self, DO_POWER_INRUSH, DO_POWER_PAGABLE, DevicePower as DevicePowerDetail, PowerActionDetail,
    PowerState, power_action_flag_names, power_action_state_name, power_minor_name,
};
use crate::types::VirtAddr;

shapes! {
    /// A driver, found from one of its device objects or its driver object.
    PowerDriver {
        driver_object: VirtAddr,
        /// The driver object's name, as `!drvobj` shows it; empty when it
        /// has none.
        name: String,
        driver_start: VirtAddr,
        /// The loaded module that holds `driver_start`, such as
        /// `viostor.sys`.
        module: Option<String>,
    }

    /// A power state.
    PowerStateValue {
        /// `system` or `device`.
        kind: &'static str,
        value: u64,
        /// The state's name, such as `Working`, `Hibernate`, or `D3`, or the
        /// value in hex when the PDB has no name for it.
        name: String,
    }

    /// Where an IRP is pending: the driver of its current stack location.
    PowerIrpHolder {
        /// `CurrentLocation`, counted from 1 as `!irp` does.
        location: u8,
        stack_count: u8,
        stack_location: VirtAddr,
        major_function: Hex<u8>,
        minor_function: Hex<u8>,
        /// The state that the location's power request asks for.
        state: Option<PowerStateValue>,
        /// Whether the location's driver returned `STATUS_PENDING`.
        pending_returned: bool,
        device: VirtAddr,
        driver: Diag<PowerDriver>,
    }

    /// A power IRP the power manager allocated (`_POP_IRP_DATA`).
    PowerIrp {
        /// The `_POP_IRP_DATA`.
        data: VirtAddr,
        irp: VirtAddr,
        pdo: VirtAddr,
        /// The device that the IRP was sent to, the top of the PDO's stack.
        target_device: VirtAddr,
        /// The device the power manager passed it to last, or 0.
        current_device: VirtAddr,
        minor_function: Hex<u8>,
        /// `IRP_MN_SET_POWER`, `IRP_MN_QUERY_POWER`, `IRP_MN_WAIT_WAKE`, or
        /// `IRP_MN_POWER_SEQUENCE`.
        minor_name: Option<&'static str>,
        /// The requested state; for a wait/wake IRP, the deepest system
        /// state it can wake the system from.
        state: PowerStateValue,
        /// Whether the IRP is part of a system power transition.
        system_transition: bool,
        /// The watchdog state: `Disabled`, `Enabled`, or `Completed`.
        watchdog: String,
        /// How long ago the watchdog was armed, in milliseconds. `None` when
        /// the watchdog never ran or the current time is unreadable.
        pending_ms: Option<u64>,
        /// Where the IRP is pending now.
        holder: Diag<PowerIrpHolder>,
    }

    /// The power IRPs on a list of `_POP_IRP_DATA`.
    PowerIrpList {
        head: VirtAddr,
        /// The symbol of the head, such as `nt!PopIrpList`.
        head_name: Option<&'static str>,
        /// Each entry, or why it does not decode.
        irps: Vec<Diag<PowerIrp>>,
        /// Why the walk stopped before the head.
        stopped: Option<String>,
    }

    /// A thread that passes power IRPs to drivers.
    PowerWorker {
        thread: VirtAddr,
        /// The IRP that it is passing to a driver, or 0 while it waits.
        irp: VirtAddr,
        device: VirtAddr,
        /// The driver of `device`.
        driver: Option<String>,
        /// Whether the power manager keeps the thread when there is no work.
        is_static: bool,
    }

    /// The power IRP worker threads on a list of `_POP_IRP_WORKER_ENTRY`.
    PowerWorkerList {
        head: VirtAddr,
        /// The symbol of the head, such as `nt!PopIrpThreadList`.
        head_name: Option<&'static str>,
        workers: Vec<Diag<PowerWorker>>,
        stopped: Option<String>,
    }

    /// The device notification pass of a system power action
    /// (`PopAction.DevState`).
    DeviceNotifyState {
        address: VirtAddr,
        irp_minor: Hex<u8>,
        system_state: String,
        thread: VirtAddr,
        status: Hex<u32>,
        failed_device: VirtAddr,
        waking: bool,
        cancelled: bool,
    }

    /// The system power action, the power IRPs, and the IRP worker threads
    /// (`!poaction`).
    PowerAction {
        /// `nt!PopAction`.
        address: VirtAddr,
        state: u8,
        /// `Idle`, `NewRequest`, `Callout`, or `SetSystemState`.
        state_name: Option<&'static str>,
        updates: u8,
        shutdown: bool,
        /// The action, such as `None`, `Sleep`, or `Hibernate`.
        action: String,
        lightest_state: String,
        flags: Hex<u32>,
        /// The `POWER_ACTION_*` flags, such as `QUERY_ALLOWED`.
        flag_names: Vec<&'static str>,
        status: Hex<u32>,
        irp_minor: Hex<u8>,
        waking: bool,
        /// The system state being entered.
        system_state: String,
        next_system_state: String,
        effective_system_state: String,
        current_system_state: String,
        hiber_context: VirtAddr,
        action_worker_thread: VirtAddr,
        /// The device notification pass in progress. `None` when there is
        /// none.
        devices: Option<Diag<DeviceNotifyState>>,
        /// The power IRPs on `nt!PopIrpList`.
        irps: Diag<PowerIrpList>,
        /// The IRP worker threads on `nt!PopIrpThreadList`.
        workers: Diag<PowerWorkerList>,
    }

    /// The idle detection a driver registered with
    /// `PoRegisterDeviceForIdleDetection`.
    PowerIdleDetection {
        /// The `_DEVICE_OBJECT_POWER_EXTENSION`.
        address: VirtAddr,
        idle_count: u32,
        busy_count: u32,
        busy_reference: u32,
        total_busy_count: u32,
        /// Seconds idle before the power manager powers the device down,
        /// on battery.
        conservation_idle_time: u32,
        /// Seconds idle before the power manager powers the device down,
        /// on AC power.
        performance_idle_time: u32,
        idle_type: String,
        /// The device state requested when the device idles.
        idle_state: String,
        current_state: String,
    }

    /// The power fields of the device node of a device's stack.
    DevNodePower {
        address: VirtAddr,
        instance_path: String,
        /// The device state of the PDO, as PnP records it.
        current_state: String,
        /// The device's `_POP_FX_DEVICE`, or 0 when its driver did not
        /// register with the power framework.
        fx_device: VirtAddr,
        /// The device power IRP the power framework has outstanding.
        fx_pending_irp: Option<VirtAddr>,
    }

    /// A device object's power state (`!podev`).
    DevicePower {
        device: VirtAddr,
        driver: Diag<PowerDriver>,
        /// `DEVICE_OBJECT.Flags`.
        flags: Hex<u32>,
        /// `DO_POWER_PAGABLE`: the driver handles power IRPs at
        /// PASSIVE_LEVEL.
        power_pagable: bool,
        /// `DO_POWER_INRUSH`: the device draws inrush current at power-up.
        power_inrush: bool,
        /// The `_DEVOBJ_EXTENSION`.
        extension: VirtAddr,
        power_flags: Hex<u32>,
        /// The last system state the driver set with `PoSetPowerState`.
        system_state: String,
        /// The last device state the driver set with `PoSetPowerState`.
        device_state: String,
        /// The idle detection the driver registered. `None` when it did
        /// not.
        idle: Option<Diag<PowerIdleDetection>>,
        /// The device node of the stack. `None` when there is none.
        devnode: Option<Diag<DevNodePower>>,
        /// The power IRPs on `nt!PopIrpList` sent to the device's stack.
        irps: Diag<Vec<PowerIrp>>,
    }
}

fn diag<T, U>(
    value: &std::result::Result<T, String>,
    build: impl FnOnce(&T) -> U,
) -> DiagnosticValue<U> {
    match value {
        Ok(value) => DiagnosticValue::Available(build(value)),
        Err(error) => DiagnosticValue::unavailable(error.clone()),
    }
}

pub fn power_driver(driver: &power::DeviceDriver) -> PowerDriver {
    PowerDriver {
        driver_object: driver.driver_object,
        name: driver.name.clone(),
        driver_start: driver.driver_start,
        module: driver.module.clone(),
    }
}

fn power_state(state: &PowerState) -> PowerStateValue {
    let (kind, value) = match state {
        PowerState::System(value) => ("system", value),
        PowerState::Device(value) => ("device", value),
    };
    PowerStateValue {
        kind,
        value: value.value,
        name: value.label(),
    }
}

pub fn power_irp_holder(holder: &power::IrpHolder) -> PowerIrpHolder {
    PowerIrpHolder {
        location: holder.location,
        stack_count: holder.stack_count,
        stack_location: holder.stack_location,
        major_function: holder.major_function,
        minor_function: holder.minor_function,
        state: holder.state.as_ref().map(power_state),
        pending_returned: holder.pending_returned,
        device: holder.device,
        driver: diag(&holder.driver, power_driver),
    }
}

pub fn power_irp(irp: &power::PowerIrp) -> PowerIrp {
    PowerIrp {
        data: irp.data,
        irp: irp.irp,
        pdo: irp.pdo,
        target_device: irp.target_device,
        current_device: irp.current_device,
        minor_function: irp.minor_function,
        minor_name: power_minor_name(irp.minor_function),
        state: power_state(&irp.state),
        system_transition: irp.system_transition,
        watchdog: irp.watchdog.label(),
        pending_ms: irp.pending.map(|pending| pending / 10_000),
        holder: diag(&irp.holder, power_irp_holder),
    }
}

pub fn power_irp_list(list: &power::PowerIrpList) -> PowerIrpList {
    PowerIrpList {
        head: list.head,
        head_name: list.head_name,
        irps: list
            .entries
            .iter()
            .map(|entry| match &entry.irp {
                Ok(irp) => DiagnosticValue::Available(power_irp(irp)),
                Err(error) => {
                    DiagnosticValue::unavailable(format!("entry {:#x}: {error}", entry.data.0))
                }
            })
            .collect(),
        stopped: list.stopped.clone(),
    }
}

pub fn power_worker_list(list: &power::PowerWorkerList) -> PowerWorkerList {
    PowerWorkerList {
        head: list.head,
        head_name: list.head_name,
        workers: list
            .entries
            .iter()
            .map(|entry| match &entry.worker {
                Ok(worker) => DiagnosticValue::Available(PowerWorker {
                    thread: worker.thread,
                    irp: worker.irp,
                    device: worker.device,
                    driver: worker.driver.clone(),
                    is_static: worker.is_static,
                }),
                Err(error) => {
                    DiagnosticValue::unavailable(format!("entry {:#x}: {error}", entry.entry.0))
                }
            })
            .collect(),
        stopped: list.stopped.clone(),
    }
}

/// `!poaction`.
pub fn power_action(detail: &PowerActionDetail) -> PowerAction {
    let action = &detail.action;
    PowerAction {
        address: action.address,
        state: action.state,
        state_name: power_action_state_name(action.state),
        updates: action.updates,
        shutdown: action.shutdown,
        action: action.action.label(),
        lightest_state: action.lightest_state.label(),
        flags: action.flags,
        flag_names: power_action_flag_names(action.flags),
        status: action.status,
        irp_minor: action.irp_minor,
        waking: action.waking,
        system_state: action.system_state.label(),
        next_system_state: action.next_system_state.label(),
        effective_system_state: action.effective_system_state.label(),
        current_system_state: action.current_system_state.label(),
        hiber_context: action.hiber_context,
        action_worker_thread: action.action_worker_thread,
        devices: action.devices.as_ref().map(|devices| {
            diag(devices, |state| DeviceNotifyState {
                address: state.address,
                irp_minor: state.irp_minor,
                system_state: state.system_state.label(),
                thread: state.thread,
                status: state.status,
                failed_device: state.failed_device,
                waking: state.waking,
                cancelled: state.cancelled,
            })
        }),
        irps: diag(&detail.irps, power_irp_list),
        workers: diag(&detail.workers, power_worker_list),
    }
}

/// `!podev`.
pub fn device_power(detail: &DevicePowerDetail) -> DevicePower {
    DevicePower {
        device: detail.device,
        driver: diag(&detail.driver, power_driver),
        flags: detail.flags,
        power_pagable: detail.flags & DO_POWER_PAGABLE != 0,
        power_inrush: detail.flags & DO_POWER_INRUSH != 0,
        extension: detail.extension,
        power_flags: detail.power_flags,
        system_state: detail.system_state.label(),
        device_state: detail.device_state.label(),
        idle: detail.idle.as_ref().map(|idle| {
            diag(idle, |idle| PowerIdleDetection {
                address: idle.address,
                idle_count: idle.idle_count,
                busy_count: idle.busy_count,
                busy_reference: idle.busy_reference,
                total_busy_count: idle.total_busy_count,
                conservation_idle_time: idle.conservation_idle_time,
                performance_idle_time: idle.performance_idle_time,
                idle_type: idle.idle_type.label(),
                idle_state: idle.idle_state.label(),
                current_state: idle.current_state.label(),
            })
        }),
        devnode: detail.devnode.as_ref().map(|node| {
            diag(node, |node| DevNodePower {
                address: node.address,
                instance_path: node.instance_path.clone(),
                current_state: node.current_state.label(),
                fx_device: node.fx_device,
                fx_pending_irp: node.fx_pending_irp,
            })
        }),
        irps: diag(&detail.irps, |irps| irps.iter().map(power_irp).collect()),
    }
}
