//! Power management: the system power action and its power IRPs
//! (`!poaction`), a device's power state (`!podev`), and the system power
//! policy (`!popolicy`).

use crate::repl::*;
use crate::target::power::{
    DO_POWER_INRUSH, DO_POWER_PAGABLE, DevicePower, IRP_MJ_POWER, IrpHolder, PowerActionDetail,
    PowerIrp, PowerIrpList, PowerPolicy, PowerState, PowerWorkerList, dynamic_throttle_name,
    power_action_flag_names, power_action_state_name, power_event_code_names, power_minor_name,
};
use crate::ui;

repl_command! {
    cmd_poaction;
    names: ["!poaction", "poaction"],
    usage: "!poaction",
    summary: "Show the system power action and the power IRPs in flight.",
    details: "Shows nt!PopAction: the power action in progress, its state and flags, and the system state being entered, with the device notification pass when one runs. Then lists every power IRP the power manager has allocated, from nt!PopIrpList: its PDO, the device it was sent to, its minor function and the power state it asks for, where it is pending now (the driver of its current stack location), and how long the drivers have had it when the power IRP watchdog runs. Last come the threads that pass power IRPs to drivers, from nt!PopIrpThreadList, with the IRP and device each is working on.",
    target: Kernel,
}

repl_command! {
    cmd_podev;
    names: ["!podev", "podev"],
    usage: "!podev <device-object>",
    summary: "Show the power state of a device object.",
    details: "Shows the device's driver and power flags, the system and device power states its driver last set with PoSetPowerState (from the PowerFlags of its DEVOBJ_EXTENSION), the idle detection the driver registered, if any, the device state PnP records in the device node of the stack, whether the driver registered with the power framework and the device power IRP that it has outstanding, and the power IRPs on nt!PopIrpList sent to any device of the stack.",
    completion: Expression,
    target: Kernel,
}

repl_command! {
    cmd_popolicy;
    names: ["!popolicy", "popolicy"],
    usage: "!popolicy [address]",
    summary: "Show the system power policy in effect.",
    details: "Decodes the SYSTEM_POWER_POLICY that nt!PopPolicy points to, or the one at the address you give: the action for the power button, the sleep button, closing the lid, idling, and overheating, with each action's flags and notification events, the idle timeout and sensitivity, the lightest and deepest sleep states, the display and disk timeouts, the throttling settings, and the battery discharge levels.",
    completion: Expression,
    target: Kernel,
}

/// A time in 100 ns units, in seconds to a tenth.
pub fn duration_text(units: u64) -> String {
    let tenths = units / 1_000_000;
    format!("{}.{} s", tenths / 10, tenths % 10)
}

/// `IRP_MJ_POWER IRP_MN_SET_POWER D3`.
pub fn request_text(major: u8, minor: u8, state: Option<&PowerState>) -> String {
    if major != IRP_MJ_POWER {
        return format!("major {major:#x} minor {minor:#x}");
    }
    let minor = power_minor_name(minor).map_or_else(|| format!("minor {minor:#x}"), str::to_string);
    match state {
        Some(state) => format!("IRP_MJ_POWER {minor} {}", state.label()),
        None => format!("IRP_MJ_POWER {minor}"),
    }
}

/// `\Driver\USBHUB3 (USBHUB3.SYS) device ffff…, stack location 11 of 14`.
pub fn holder_text(holder: &IrpHolder) -> String {
    let driver = match &holder.driver {
        Ok(driver) => ui::symbol(&driver.label()),
        Err(error) => ui::muted(&format!("driver unreadable: {error}")),
    };
    format!(
        "{driver}  device {}  stack location {} of {}{}",
        ui::addr(holder.device.0),
        holder.location,
        holder.stack_count,
        if holder.pending_returned {
            "  (returned STATUS_PENDING)"
        } else {
            ""
        }
    )
}

fn print_power_irp(irp: &PowerIrp, indent: &str) {
    let minor = power_minor_name(irp.minor_function).map_or_else(
        || format!("minor {:#x}", irp.minor_function),
        str::to_string,
    );
    outln!(
        "{indent}IRP {}  {} {}  PDO {}",
        ui::addr(irp.irp.0),
        minor,
        irp.state.label(),
        ui::addr(irp.pdo.0)
    );
    outln!(
        "{indent}  {} {}{}",
        ui::muted("sent to   "),
        ui::addr(irp.target_device.0),
        if irp.current_device.is_zero() {
            String::new()
        } else {
            format!("  current device {}", ui::addr(irp.current_device.0))
        }
    );
    match &irp.holder {
        Ok(holder) => outln!(
            "{indent}  {} {}",
            ui::muted("pending in"),
            holder_text(holder)
        ),
        Err(error) => outln!(
            "{indent}  {} {}",
            ui::muted("pending in"),
            ui::muted(&format!("unknown: {error}"))
        ),
    }
    let watchdog = match irp.pending {
        Some(pending) => format!(
            "{}, armed {} ago",
            irp.watchdog.label(),
            duration_text(pending)
        ),
        None => irp.watchdog.label(),
    };
    outln!(
        "{indent}  {} {}{}  {}",
        ui::muted("watchdog  "),
        watchdog,
        if irp.system_transition {
            "  system transition"
        } else {
            ""
        },
        ui::muted(&format!("POP_IRP_DATA {}", ui::addr(irp.data.0)))
    );
}

fn list_title(title: &str, head_name: Option<&str>, head: u64) -> String {
    match head_name {
        Some(name) => format!("{title} ({name} {})", ui::addr(head)),
        None => format!("{title} (list {})", ui::addr(head)),
    }
}

pub fn print_power_irp_list(list: &PowerIrpList, indent: &str) {
    outln!(
        "{indent}{}",
        list_title("Allocated power IRPs", list.head_name, list.head.0)
    );
    if list.entries.is_empty() && list.stopped.is_none() {
        outln!("{indent}  none");
    }
    for entry in &list.entries {
        match &entry.irp {
            Ok(irp) => print_power_irp(irp, &format!("{indent}  ")),
            Err(error) => outln!(
                "{indent}  {} {}",
                ui::addr(entry.data.0),
                ui::muted(&format!("unreadable: {error}"))
            ),
        }
    }
    if let Some(stopped) = &list.stopped {
        outln!(
            "{indent}  {}",
            ui::muted(&format!("walk stopped: {stopped}"))
        );
    }
}

pub fn print_power_worker_list(list: &PowerWorkerList, indent: &str) {
    outln!(
        "{indent}{}",
        list_title("IRP worker threads", list.head_name, list.head.0)
    );
    if list.entries.is_empty() && list.stopped.is_none() {
        outln!("{indent}  none");
    }
    for entry in &list.entries {
        match &entry.worker {
            Ok(worker) => {
                let kind = if worker.is_static {
                    "static"
                } else {
                    "dynamic"
                };
                if worker.irp.is_zero() {
                    outln!(
                        "{indent}  THREAD {} ({kind})  waiting for work",
                        ui::addr(worker.thread.0)
                    );
                } else {
                    outln!(
                        "{indent}  THREAD {} ({kind})  IRP {}  device {}{}",
                        ui::addr(worker.thread.0),
                        ui::addr(worker.irp.0),
                        ui::addr(worker.device.0),
                        worker
                            .driver
                            .as_deref()
                            .map(|driver| format!("  {}", ui::symbol(driver)))
                            .unwrap_or_default()
                    );
                }
            }
            Err(error) => outln!(
                "{indent}  {} {}",
                ui::addr(entry.entry.0),
                ui::muted(&format!("unreadable: {error}"))
            ),
        }
    }
    if let Some(stopped) = &list.stopped {
        outln!(
            "{indent}  {}",
            ui::muted(&format!("walk stopped: {stopped}"))
        );
    }
}

fn flags_text(flags: u32, names: Vec<&str>) -> String {
    if names.is_empty() {
        format!("{flags:08x}")
    } else {
        format!("{flags:08x} {}", names.join("|"))
    }
}

fn print_power_action(detail: &PowerActionDetail) {
    let action = &detail.action;
    outln!("PopAction: {}", ui::addr(action.address.0));
    outln!(
        "  State..........: {} - {}",
        action.state,
        power_action_state_name(action.state).unwrap_or("unknown")
    );
    outln!("  Updates........: {}", action.updates);
    outln!("  Action.........: {}", action.action.label());
    outln!("  Lightest State.: {}", action.lightest_state.label());
    outln!(
        "  Flags..........: {}",
        flags_text(action.flags, power_action_flag_names(action.flags))
    );
    outln!("  Irp minor......: {:#x}", action.irp_minor);
    outln!("  System State...: {}", action.system_state.label());
    outln!("  Next State.....: {}", action.next_system_state.label());
    outln!(
        "  Effective State: {}",
        action.effective_system_state.label()
    );
    outln!("  Current State..: {}", action.current_system_state.label());
    outln!("  Status.........: {:#010x}", action.status);
    outln!(
        "  Shutdown.......: {}  Waking: {}",
        action.shutdown,
        action.waking
    );
    outln!("  Hiber Context..: {}", ui::addr(action.hiber_context.0));
    outln!(
        "  Worker Thread..: {}",
        ui::addr(action.action_worker_thread.0)
    );
    match &action.devices {
        None => outln!("  Device notification: none in progress"),
        Some(Ok(devices)) => {
            outln!(
                "  Device notification {}: minor {:#x}, {}, thread {}, status {:#010x}{}{}{}",
                ui::addr(devices.address.0),
                devices.irp_minor,
                devices.system_state.label(),
                ui::addr(devices.thread.0),
                devices.status,
                if devices.failed_device.is_zero() {
                    String::new()
                } else {
                    format!(", failed device {}", ui::addr(devices.failed_device.0))
                },
                if devices.waking { ", waking" } else { "" },
                if devices.cancelled { ", cancelled" } else { "" }
            );
        }
        Some(Err(error)) => outln!(
            "  Device notification: {}",
            ui::muted(&format!("unreadable: {error}"))
        ),
    }
    outln!();
    match &detail.irps {
        Ok(list) => print_power_irp_list(list, ""),
        Err(error) => error!("power IRP list: {error}"),
    }
    outln!();
    match &detail.workers {
        Ok(list) => print_power_worker_list(list, ""),
        Err(error) => error!("IRP worker list: {error}"),
    }
}

fn print_device_power(power: &DevicePower) {
    outln!("Device object {} is for:", ui::addr(power.device.0));
    match &power.driver {
        Ok(driver) => outln!("  {}", ui::symbol(&driver.label())),
        Err(error) => outln!("  {}", ui::muted(&format!("driver unreadable: {error}"))),
    }
    let mut device_flags = Vec::new();
    if power.flags & DO_POWER_PAGABLE != 0 {
        device_flags.push("DO_POWER_PAGABLE");
    }
    if power.flags & DO_POWER_INRUSH != 0 {
        device_flags.push("DO_POWER_INRUSH");
    }
    outln!("  Flags {}", flags_text(power.flags, device_flags));
    outln!("DevObjExtension: {}", ui::addr(power.extension.0));
    outln!(
        "PowerFlags: {:08x} => SystemState={} DeviceState={}",
        power.power_flags,
        power.system_state.label(),
        power.device_state.label()
    );
    match &power.idle {
        None => outln!("Idle detection: not registered"),
        Some(Ok(idle)) => {
            outln!("Idle detection: {}", ui::addr(idle.address.0));
            outln!(
                "  IdleCount {}  BusyCount {}  BusyReference {}  TotalBusyCount {}",
                idle.idle_count,
                idle.busy_count,
                idle.busy_reference,
                idle.total_busy_count
            );
            outln!(
                "  ConservationIdleTime {} s  PerformanceIdleTime {} s",
                idle.conservation_idle_time,
                idle.performance_idle_time
            );
            outln!(
                "  IdleType {}  IdleState {}  CurrentState {}",
                idle.idle_type.label(),
                idle.idle_state.label(),
                idle.current_state.label()
            );
        }
        Some(Err(error)) => outln!(
            "Idle detection: {}",
            ui::muted(&format!("unreadable: {error}"))
        ),
    }
    match &power.devnode {
        None => outln!("DevNode: none"),
        Some(Ok(node)) => {
            outln!(
                "DevNode {} \"{}\"",
                ui::addr(node.address.0),
                node.instance_path
            );
            outln!("  CurrentPowerState: {}", node.current_state.label());
            if node.fx_device.is_zero() {
                outln!("  Power framework: not registered");
            } else {
                outln!(
                    "  Power framework: {}{}",
                    ui::addr(node.fx_device.0),
                    match node.fx_pending_irp {
                        Some(irp) if !irp.is_zero() =>
                            format!("  pending device power IRP {}", ui::addr(irp.0)),
                        _ => String::new(),
                    }
                );
            }
        }
        Some(Err(error)) => outln!("DevNode: {}", ui::muted(&format!("unreadable: {error}"))),
    }
    match &power.irps {
        Ok(irps) if irps.is_empty() => outln!("Power IRPs for the stack: none"),
        Ok(irps) => {
            outln!("Power IRPs for the stack (nt!PopIrpList):");
            for irp in irps {
                print_power_irp(irp, "  ");
            }
        }
        Err(error) => outln!(
            "Power IRPs for the stack: {}",
            ui::muted(&format!("unavailable: {error}"))
        ),
    }
}

fn print_power_policy(policy: &PowerPolicy) {
    outln!(
        "SYSTEM_POWER_POLICY (R.{}) @ {}",
        policy.revision,
        ui::addr(policy.address.0)
    );
    for (name, action) in &policy.actions {
        let flags = power_action_flag_names(action.flags);
        let events = power_event_code_names(action.event_code);
        outln!(
            "  {:<15}{:>14}  Flags: {:08x}  Event: {:08x}{}",
            format!("{name}:"),
            action.action.label(),
            action.flags,
            action.event_code,
            flags
                .iter()
                .chain(events.iter())
                .map(|name| format!(" {name}"))
                .collect::<String>()
        );
    }
    outln!(
        "  {:<22}{:>8}  {:<22}{:>7}%",
        "IdleTimeout:",
        policy.idle_timeout,
        "IdleSensitivity:",
        policy.idle_sensitivity
    );
    outln!(
        "  {:<22}{:>8}  {:<22}{:>8}",
        "MinSleep:",
        policy.min_sleep.label(),
        "MaxSleep:",
        policy.max_sleep.label()
    );
    outln!(
        "  {:<22}{:>8}  {:<22}{:>8}",
        "LidOpenWake:",
        policy.lid_open_wake.label(),
        "ReducedLatencySleep:",
        policy.reduced_latency_sleep.label()
    );
    outln!(
        "  {:<22}{:>8}  {:<22}{:>8}",
        "WinLogonFlags:",
        policy.win_logon_flags,
        "DozeS4Timeout:",
        policy.doze_s4_timeout
    );
    outln!(
        "  {:<22}{:>8}  {:<22}{:>8}",
        "VideoTimeout:",
        policy.video_timeout,
        "VideoDimDisplay:",
        policy.video_dim_display
    );
    outln!(
        "  {:<22}{:>8}  {:<22}{:>8}",
        "SpindownTimeout:",
        policy.spindown_timeout,
        "OptimizeForPower:",
        policy.optimize_for_power
    );
    outln!(
        "  {:<22}{:>7}%  {:<22}{:>7}%",
        "FanThrottleTolerance:",
        policy.fan_throttle_tolerance,
        "ForcedThrottle:",
        policy.forced_throttle
    );
    outln!(
        "  {:<22}{:>7}%  {:<22}{:>8}",
        "MinThrottle:",
        policy.min_throttle,
        "DynamicThrottle:",
        dynamic_throttle_name(policy.dynamic_throttle)
            .map_or_else(|| policy.dynamic_throttle.to_string(), str::to_string)
    );
    outln!(
        "  {:<22}{:>8}",
        "BroadcastCapacity:",
        policy.broadcast_capacity_resolution
    );
    for (index, level) in policy.discharge.iter().enumerate() {
        outln!(
            "  Discharge[{index}]: {}  battery {}%  {}  Flags: {:08x}  Event: {:08x}  min {}",
            if level.enabled {
                "enabled "
            } else {
                "disabled"
            },
            level.battery_level,
            level.policy.action.label(),
            level.policy.flags,
            level.policy.event_code,
            level.min_system_state.label()
        );
    }
}

impl ReplState<'_> {
    fn cmd_poaction(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match self.ctx.target.power_action() {
            Ok(detail) => print_power_action(&detail),
            Err(error) => error!("!poaction: {error}"),
        }
        Ok(())
    }

    fn cmd_podev(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        let Some(device) = self.eval_or_report(invocation.arg(0).unwrap_or_default()) else {
            return Ok(());
        };
        match self.ctx.target.device_power(device) {
            Ok(power) => print_device_power(&power),
            Err(error) => error!("!podev: {error}"),
        }
        Ok(())
    }

    fn cmd_popolicy(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let address = match invocation.argv.len() {
            0 => None,
            1 => match self.eval_or_report(invocation.arg(0).unwrap_or_default()) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        };
        match self.ctx.target.power_policy(address) {
            Ok(policy) => print_power_policy(&policy),
            Err(error) => error!("!popolicy: {error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_seconds_to_a_tenth() {
        assert_eq!(duration_text(0), "0.0 s");
        assert_eq!(duration_text(9_999_999), "0.9 s");
        assert_eq!(duration_text(1_205_000_000), "120.5 s");
    }
}
