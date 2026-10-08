//! A crash dump's tagged data (`.enumtag`) and the Windows blackbox records
//! in it (`!blackboxbsd`, `!blackboxntfs`, `!blackboxpnp`,
//! `!blackboxwinlogon`, `!blackboxpci`), as WinDbg shows them.

use std::sync::Arc;

use crate::blackbox::{
    BSD_TAG, BootStatus, NTFS_OPLOCK_BREAK_TIMEOUT, NTFS_SLOW_IO_TIMEOUT, NTFS_TAG, PCI_TAG,
    PNP_TAG, WINLOGON_TAG, decode_boot_status, decode_ntfs, decode_pci, decode_pnp,
    decode_winlogon, feature_configuration_state_name, ntfs_break_reason_name,
    ntfs_record_kind_name, pci_command_flags, pci_status_flags, tagged_block,
};
use crate::dmp::tagged::{TaggedBlock, known_tag};
use crate::error::Result;
use crate::target::etw::{format_guid, parse_guid};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_enumtag;
    names: [".enumtag"],
    usage: ".enumtag [tag]",
    summary: "List the tagged data blocks that bugcheck callbacks added to the crash dump.",
    details: "Each block shows its GUID tag, its size, who writes it, and its first bytes; with a tag, every byte of that block. A tag that Windows writes names its global and what it holds, such as nt!PopBlackBoxPnpGuid, the PnP blackbox that !blackboxpnp decodes. For another tag, such as a driver's KBUGCHECK_REASON_CALLBACK data, ntoseye looks for its bytes in the kernel modules' images and names the global that holds it, when the dump has the image and its symbols are loaded. The SDK reads a block with Debugger.read_tagged.",
    completion: None,
}

repl_command! {
    cmd_blackboxbsd;
    names: ["!blackboxbsd"],
    usage: "!blackboxbsd",
    summary: "Show the boot status data (bootstat.dat) the crash dump recorded.",
    details: "Whether the last boot succeeded and shut down, the boot IDs of the last successful and abnormal shutdowns, the power transition and power button state, and the feature configuration state, as WinDbg's !blackboxbsd shows them.",
    completion: None,
}

repl_command! {
    cmd_blackboxntfs;
    names: ["!blackboxntfs"],
    usage: "!blackboxntfs",
    summary: "Show the NTFS slow I/O and oplock break timeouts the crash dump recorded.",
    details: "Each record shows its type and length; a slow I/O timeout its IRP, SCB, and waiting thread, and an oplock break timeout its reason (the NTFS routine), IRP, SCB, and the owning and breaking processes, as WinDbg's !blackboxntfs shows them.",
    completion: None,
}

repl_command! {
    cmd_blackboxpnp;
    names: ["!blackboxpnp"],
    usage: "!blackboxpnp",
    summary: "Show the PnP event the crash dump recorded.",
    details: "The PnP activity, its time, the event, whether it was in progress, the device's problem code, the veto, and the device instance ID, as WinDbg's !blackboxpnp shows them.",
    completion: None,
}

repl_command! {
    cmd_blackboxwinlogon;
    names: ["!blackboxwinlogon"],
    usage: "!blackboxwinlogon",
    summary: "Show what winlogon was doing when the crash dump was written.",
    completion: None,
}

repl_command! {
    cmd_blackboxpci;
    names: ["!blackboxpci"],
    usage: "!blackboxpci",
    summary: "List the PCI functions pci.sys recorded in the crash dump, with their command and status.",
    details: "Each function shows its bus, device, and function, its vendor and device IDs and revision, and its command and status registers with their flags as WinDbg's !blackboxpci shows them: i (I/O), m (memory), b (bus master), v (VGA palette snoop), p (parity), s (SERR) for the command, and c (capability list), 6 (66 MHz), P (master data parity error), A (signaled target abort), S (signaled system error) for the status. WinDbg prints the command register's value as the status value; ntoseye prints the status register's.",
    completion: None,
}

/// How many 16-byte lines `.enumtag` shows of each block without a tag.
const ENUMTAG_PREVIEW_LINES: usize = 4;

impl ReplState<'_> {
    /// The dump's tagged blocks, or why there are none.
    fn tagged_blocks(&self, command: &str) -> Option<&[TaggedBlock]> {
        let Some(dump) = self.ctx.target.phys.dmp_info() else {
            error!("{command}: tagged data is in crash dumps; this target is live");
            return None;
        };
        if dump.tagged_blocks.is_empty() {
            error!("{command}: the dump has no tagged data");
            return None;
        }
        Some(&dump.tagged_blocks)
    }

    /// The data of the block tagged `tag`, or a message that the dump has
    /// none.
    fn blackbox_block(&self, command: &str, tag: &str, what: &str) -> Option<Arc<[u8]>> {
        let blocks = self.tagged_blocks(command)?;
        let block = tagged_block(blocks, tag);
        if block.is_none() {
            error!("{command}: the dump has no {what}");
        }
        block.map(|block| Arc::clone(&block.data))
    }

    fn cmd_enumtag(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let only = match invocation.arg(0) {
            None => None,
            Some(text) => match parse_guid(text) {
                Some(tag) => Some(tag),
                None => {
                    error!(".enumtag: '{text}' is not a GUID");
                    return Ok(());
                }
            },
        };
        let Some(blocks) = self.tagged_blocks(".enumtag") else {
            return Ok(());
        };
        let mut shown = 0;
        for block in blocks
            .iter()
            .filter(|block| only.is_none_or(|tag| block.tag == tag))
        {
            shown += 1;
            let tag = format_guid(&block.tag).to_uppercase();
            let owner = match known_tag(&block.tag) {
                Some(known) => format!("{}: {}", known.owner, known.holds),
                None => self
                    .tag_owner(&block.tag)
                    .unwrap_or_else(|| "writer not found in the dump's images".to_string()),
            };
            outln!(
                "{tag} - {:#x} bytes  {}",
                block.data.len(),
                ui::muted(&owner)
            );
            let lines = if only.is_some() {
                usize::MAX
            } else {
                ENUMTAG_PREVIEW_LINES
            };
            for line in block.data.chunks(16).take(lines) {
                let hex: Vec<String> = line.iter().map(|byte| format!("{byte:02X}")).collect();
                let text: String = line
                    .iter()
                    .map(|&byte| {
                        if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                outln!("  {:<47}  {text}", hex.join(" "));
            }
            let rest = block.data.len().saturating_sub(16 * lines);
            if rest > 0 {
                outln!(
                    "  {}",
                    ui::muted(&format!(
                        "... {rest:#x} more bytes; .enumtag {tag} shows them all"
                    ))
                );
            }
            outln!();
        }
        if shown == 0 {
            error!(".enumtag: the dump has no block with that tag");
        }
        Ok(())
    }

    /// The global that holds `tag` in a kernel module's image, for a tag
    /// that Windows does not write itself: a driver keeps the GUID it tags
    /// its data with in a global. `module+offset` when no symbol starts
    /// there.
    fn tag_owner(&self, tag: &[u8; 16]) -> Option<String> {
        let modules = self.ctx.target.kernel_modules().ok()?;
        modules.iter().find_map(|module| {
            let found = self
                .ctx
                .search(module.base_address, tag, module.size as usize)
                .ok()?;
            let hit = *found.matches.first()?;
            Some(
                match self
                    .ctx
                    .target
                    .nearest_symbol_current_context(VirtAddr(hit))
                {
                    Some((owner, name, 0)) => format!("{owner}!{name}"),
                    _ => format!("{}+{:#x}", module.short_name, hit - module.base_address.0),
                },
            )
        })
    }

    fn cmd_blackboxbsd(&mut self, _invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(data) = self.blackbox_block("!blackboxbsd", BSD_TAG, "boot status data") else {
            return Ok(());
        };
        match decode_boot_status(&data) {
            Ok(bsd) => print_boot_status(&bsd),
            Err(reason) => error!("!blackboxbsd: {reason}"),
        }
        Ok(())
    }

    fn cmd_blackboxntfs(&mut self, _invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(data) = self.blackbox_block("!blackboxntfs", NTFS_TAG, "NTFS blackbox") else {
            return Ok(());
        };
        let records = match decode_ntfs(&data) {
            Ok(records) => records,
            Err(reason) => {
                error!("!blackboxntfs: {reason}");
                return Ok(());
            }
        };
        outln!("NTFS Blackbox Data");
        let pointer = |label: &str, value: u64| {
            if value == 0 {
                outln!("        {label:<9} <null>");
            } else {
                outln!("        {label:<9} {}", ui::addr(value));
            }
        };
        for (index, record) in records.iter().enumerate() {
            outln!();
            outln!("Record {index}:");
            outln!(
                "  Record type:    {} ({})",
                record.kind,
                ntfs_record_kind_name(record.kind)
            );
            outln!("  Record length:  {}", record.length);
            match record.kind {
                NTFS_SLOW_IO_TIMEOUT => {
                    pointer("Irp:", record.irp);
                    pointer("Scb:", record.scb);
                    pointer("Thread:", record.thread.unwrap_or(0));
                }
                NTFS_OPLOCK_BREAK_TIMEOUT => {
                    let reason = record.break_reason.unwrap_or(0);
                    outln!(
                        "  Break Reason: {reason} ({})",
                        ntfs_break_reason_name(reason)
                    );
                    pointer("Irp:", record.irp);
                    pointer("Scb:", record.scb);
                    outln!(
                        "  Owner Process Name: '{}'",
                        record.owner_process_name.as_deref().unwrap_or_default()
                    );
                    outln!(
                        "  Breaking Process Name: '{}'",
                        record.breaking_process_name.as_deref().unwrap_or_default()
                    );
                }
                _ => {}
            }
        }
        let count = |kind| records.iter().filter(|record| record.kind == kind).count();
        outln!();
        outln!(
            "{} Slow I/O Timeout Records Found",
            count(NTFS_SLOW_IO_TIMEOUT)
        );
        outln!(
            "{} Oplock Break Timeout Records Found",
            count(NTFS_OPLOCK_BREAK_TIMEOUT)
        );
        outln!();
        Ok(())
    }

    fn cmd_blackboxpnp(&mut self, _invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(data) = self.blackbox_block("!blackboxpnp", PNP_TAG, "PnP blackbox") else {
            return Ok(());
        };
        match decode_pnp(&data) {
            Ok(pnp) => {
                outln!(
                    "    PnpActivityId      : {}",
                    format_guid(&pnp.activity_id).to_uppercase()
                );
                outln!("    PnpActivityTime    : {}", pnp.activity_time);
                outln!("    PnpEventInformation: {}", pnp.event_information);
                outln!("    PnpEventInProgress : {}", pnp.event_in_progress);
                outln!("    PnpProblemCode     : {}", pnp.problem_code);
                outln!("    PnpVetoType        : {}", pnp.veto_type);
                outln!("    DeviceId           : {}", pnp.device_id);
                outln!(
                    "    VetoString         : {}",
                    pnp.veto_string.unwrap_or_default()
                );
                outln!();
            }
            Err(reason) => error!("!blackboxpnp: {reason}"),
        }
        Ok(())
    }

    fn cmd_blackboxwinlogon(&mut self, _invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(data) =
            self.blackbox_block("!blackboxwinlogon", WINLOGON_TAG, "winlogon blackbox")
        else {
            return Ok(());
        };
        match decode_winlogon(&data) {
            Ok(winlogon) => {
                outln!("    ThreadName         : {}", winlogon.thread_name);
                outln!("    IsOperationPending : {}", winlogon.is_operation_pending);
                outln!();
            }
            Err(reason) => error!("!blackboxwinlogon: {reason}"),
        }
        Ok(())
    }

    fn cmd_blackboxpci(&mut self, _invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(data) = self.blackbox_block("!blackboxpci", PCI_TAG, "PCI blackbox") else {
            return Ok(());
        };
        match decode_pci(&data) {
            Ok(records) => {
                for pci in &records {
                    outln!(
                        "{:02x}:{:02x}:{:x}  {:04x}:{:04x}.{:02x}  Cmd[{:04x}:{}]  Sts[{:04x}:{}]",
                        pci.bus,
                        pci.device,
                        pci.function,
                        pci.vendor_id,
                        pci.device_id,
                        pci.revision,
                        pci.command,
                        pci_command_flags(pci.command),
                        pci.status,
                        pci_status_flags(pci.status)
                    );
                }
                outln!();
            }
            Err(reason) => error!("!blackboxpci: {reason}"),
        }
        Ok(())
    }
}

/// `0x…` as MSVC's `%#x` prints it, which leaves zero bare.
fn alt_hex(value: u64) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

fn yes(value: bool) -> &'static str {
    if value { "TRUE" } else { "FALSE" }
}

/// A FILETIME's line under its raw value, to the millisecond as WinDbg
/// prints it.
fn print_filetime(filetime: u64) {
    if filetime == 0 {
        return;
    }
    if let Some(iso) = filetime_to_iso(filetime) {
        outln!(
            "    {}.{:03}Z",
            iso.trim_end_matches('Z'),
            (filetime / 10_000) % 1000
        );
    }
}

fn print_boot_status(bsd: &BootStatus) {
    outln!("Version: {:#x}", bsd.version);
    if let Some(size) = bsd.truncated_to {
        outln!("WARNING: Truncated Data: {size:#x}");
    }
    outln!("Product type: {}", bsd.product_type);
    outln!();
    outln!("Auto advanced boot: {}", yes(bsd.auto_advanced_boot));
    outln!(
        "Advanced boot menu timeout: {}",
        bsd.advanced_boot_menu_timeout
    );
    outln!("Last boot succeeded: {}", yes(bsd.last_boot_succeeded));
    outln!("Last boot shutdown: {}", yes(bsd.last_boot_shutdown));
    outln!("Sleep in progress: {}", yes(bsd.sleep_in_progress));
    outln!();
    let transition = &bsd.power_transition;
    outln!(
        "Power button timestamp: {:#x}",
        transition.power_button_timestamp
    );
    print_filetime(transition.power_button_timestamp);
    outln!("System running: {}", yes(transition.system_running));
    outln!(
        "Connected standby in progress: {}",
        yes(transition.connected_standby_in_progress)
    );
    outln!(
        "User shutdown in progress: {}",
        yes(transition.user_shutdown_in_progress)
    );
    outln!(
        "System shutdown in progress: {}",
        yes(transition.system_shutdown_in_progress)
    );
    outln!("Sleep in progress: {}", transition.sleep_in_progress);
    outln!(
        "Connected standby scenario instance id: {}",
        transition.connected_standby_scenario_instance_id
    );
    outln!(
        "Connected standby entry reason: {}",
        transition.connected_standby_entry_reason
    );
    outln!(
        "Connected standby exit reason: {}",
        transition.connected_standby_exit_reason
    );
    outln!(
        "System sleep transitions to on: {}",
        transition.system_sleep_transitions_to_on
    );
    outln!("Last reference time: {:#x}", transition.last_reference_time);
    print_filetime(transition.last_reference_time);
    outln!(
        "Last reference time checksum: {}",
        alt_hex(u64::from(transition.last_reference_time_checksum))
    );
    outln!("Last update boot id: {}", transition.last_update_boot_id);
    outln!();
    outln!("Boot attempt count: {}", bsd.boot_attempt_count);
    outln!("Last boot checkpoint: {}", yes(bsd.last_boot_checkpoint));
    outln!("Checksum: {}", alt_hex(u64::from(bsd.checksum)));
    outln!("Last boot id: {}", bsd.last_boot_id);
    outln!(
        "Last successful shutdown boot id: {}",
        bsd.last_successful_shutdown_boot_id
    );
    outln!(
        "Last reported abnormal shutdown boot id: {}",
        bsd.last_reported_abnormal_shutdown_boot_id
    );
    outln!();
    if let Some(error) = &bsd.error_info {
        outln!("Error info boot id: {}", error.boot_id);
        outln!("Error info repeat count: {}", error.repeat_count);
        outln!("Error info other error count: {}", error.other_error_count);
        outln!("Error info code: {}", error.code);
        outln!("Error info status: {:#x}", error.status);
        outln!();
    }
    if let Some(button) = &bsd.power_button {
        outln!(
            "Power button last press time: {:#x}",
            button.last_press_time
        );
        print_filetime(button.last_press_time);
        outln!(
            "Power button cumulative press count: {}",
            button.cumulative_press_count
        );
        outln!(
            "Power button last press boot id: {}",
            button.last_press_boot_id
        );
        outln!(
            "Power button last power watchdog stage: {}",
            alt_hex(u64::from(button.last_power_watchdog_stage))
        );
        outln!(
            "Power button watchdog armed: {}",
            yes(button.watchdog_armed)
        );
        outln!(
            "Power button shutdown in progress: {}",
            yes(button.shutdown_in_progress)
        );
        outln!(
            "Power button last release time: {:#x}",
            button.last_release_time
        );
        print_filetime(button.last_release_time);
        outln!(
            "Power button cumulative release count: {}",
            button.cumulative_release_count
        );
        outln!(
            "Power button last release boot id: {}",
            button.last_release_boot_id
        );
        outln!("Power button error count: {}", button.error_count);
        outln!(
            "Power button current connected standby phase: {}",
            button.current_connected_standby_phase
        );
        outln!(
            "Power button transition latest checkpoint id: {}",
            button.transition_latest_checkpoint_id
        );
        outln!(
            "Power button transition latest checkpoint type: {}",
            button.transition_latest_checkpoint_type
        );
        outln!(
            "Power button transition latest checkpoint sequence number: {}",
            button.transition_latest_checkpoint_sequence_number
        );
        outln!();
    }
    if let Some(extension) = &bsd.transition_extension {
        outln!(
            "Power transition Shutdown Device Type: {}",
            extension.shutdown_device_type
        );
        outln!(
            "Power transition Setup In Progress: {}",
            yes(extension.setup_in_progress)
        );
        outln!(
            "Power transition OOBE In Progress: {}",
            yes(extension.oobe_in_progress)
        );
        outln!(
            "Power transition Sleep Checkpoint Source: {}",
            extension.sleep_checkpoint_source
        );
        outln!(
            "Power transition Sleep Checkpoint: {}",
            extension.sleep_checkpoint
        );
        outln!(
            "Power transition Connected Standby Entry Reason Category: {:x}",
            extension.connected_standby_entry_reason_category
        );
        outln!(
            "Power transition Connected Standby Exit Reason Category: {:x}",
            extension.connected_standby_exit_reason_category
        );
        outln!(
            "Power transition Connected Standby Entry Scenario Instance Id: {:#x}",
            extension.connected_standby_entry_scenario_instance_id
        );
        outln!();
    }
    if let Some(state) = bsd.feature_configuration_state {
        match feature_configuration_state_name(state) {
            Some(name) => outln!("Feature Configuration State : {name}"),
            None => outln!(
                "Feature Configuration State : Unknown Value ({})",
                state as i32
            ),
        }
        outln!();
    }
}
