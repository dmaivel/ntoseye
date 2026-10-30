//! A crash dump's tagged data (`.enumtag`) and the Windows blackbox records
//! in it (`!blackboxbsd`, `!blackboxntfs`, `!blackboxpnp`,
//! `!blackboxwinlogon`, `!blackboxpci`), as WinDbg shows them.

use crate::analysis::blackbox::{
    BootStatus, NTFS_OPLOCK_BREAK_TIMEOUT, NTFS_SLOW_IO_TIMEOUT, NtfsRecord, PciRecord,
    PnpBlackbox, WinlogonBlackbox, decode_boot_status, decode_ntfs, decode_pci, decode_pnp,
    decode_winlogon, feature_configuration_state_name, ntfs_break_reason_name,
    ntfs_record_kind_name, pci_command_flags, pci_status_flags, tagged_block,
};
use crate::base::error::{Error, Result};
use crate::base::time::filetime_to_iso;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::dmp::tagged::{
    BSD_TAG, NTFS_TAG, PCI_TAG, PNP_TAG, TaggedBlock, WINLOGON_TAG, known_tag,
};
use crate::nt::target::etw::{GuidStyle, format_guid, parse_guid};
use crate::session::Session;
use ntoseye_macros::{command, grammar};

/// How many 16-byte lines `.enumtag` shows of each block without a tag.
const ENUMTAG_PREVIEW_LINES: usize = 4;

/// The dump's tagged blocks, which may be none; an error on a live target,
/// which has no dump to hold them.
fn tagged_blocks<'s>(session: &'s Session, command: &str) -> Result<&'s [TaggedBlock]> {
    let Some(dump) = session.target.phys.dmp_info() else {
        return Err(Error::DebugInfo(format!(
            "{command}: tagged data is in crash dumps; this target is live"
        )));
    };
    Ok(&dump.tagged_blocks)
}

/// The data of the block tagged `tag`, or that the dump has none. The SDK
/// method behind each blackbox command raises for a missing block, so the
/// command reports it as an error too, naming what is missing.
fn blackbox_block<'s>(
    session: &'s Session,
    command: &str,
    tag: &[u8; 16],
    what: &str,
) -> Result<&'s [u8]> {
    let blocks = tagged_blocks(session, command)?;
    tagged_block(blocks, tag)
        .map(|block| &*block.data)
        .ok_or_else(|| {
            let why = if blocks.is_empty() {
                "it records no tagged data"
            } else {
                "no tagged block holds it (.enumtag lists the blocks)"
            };
            Error::DebugInfo(format!("{command}: the dump has no {what}: {why}"))
        })
}

/// A blackbox decoder's failure, prefixed with its command.
fn decoded<T>(command: &str, result: std::result::Result<T, String>) -> Result<T> {
    result.map_err(|reason| Error::DebugInfo(format!("{command}: {reason}")))
}

/// List the tagged data blocks that bugcheck callbacks added to the crash
/// dump.
///
/// Each block shows its GUID tag, its size, who writes it, and its first
/// bytes; with a tag, every byte of that block. A tag that Windows writes
/// names its global and what it holds, such as nt!PopBlackBoxPnpGuid, the PnP
/// blackbox that !blackboxpnp decodes. For another tag, such as a driver's
/// KBUGCHECK_REASON_CALLBACK data, ntoseye looks for its bytes in the kernel
/// modules' images and names the global that holds it, when the dump has the
/// image and its symbols are loaded. The SDK reads a block with
/// Debugger.read_tagged.
#[command(
    names = [".enumtag"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn enumtag(
    state: &mut ReplState<'_>,
    #[arg(parse = enumtag_tag)] only: Option<[u8; 16]>,
) -> Result<()> {
    let blocks = tagged_blocks(state.ctx, ".enumtag")?;
    if blocks.is_empty() {
        outln!("{}", ui::muted("no tagged data in this dump"));
        return Ok(());
    }
    let mut shown = 0;
    for block in blocks
        .iter()
        .filter(|block| only.is_none_or(|tag| block.tag == tag))
    {
        shown += 1;
        let tag = format_guid(&block.tag, GuidStyle::BracedUpper);
        let owner = match known_tag(&block.tag) {
            Some(known) => format!("{}: {}", known.owner, known.holds),
            None => tag_owner(state.ctx, &block.tag)
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
            let (hex, text) = hex_ascii_row(line, HexCase::Upper);
            outln!("  {hex:<47}  {text}");
        }
        let rest = block.data.len().saturating_sub(lines.saturating_mul(16));
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
    if let (0, Some(tag)) = (shown, only) {
        outln!(
            "{}",
            ui::muted(&format!(
                "no tagged data block matching '{}'",
                format_guid(&tag, GuidStyle::BracedUpper)
            ))
        );
    }
    Ok(())
}

/// `.enumtag`'s tag, a GUID.
#[grammar(usage = "[tag]")]
fn enumtag_tag(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<[u8; 16]>, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(None);
    };
    parse_guid(&text)
        .map(Some)
        .ok_or_else(|| ArgError::Message(format!(".enumtag: '{text}' is not a GUID")))
}

/// The global that holds `tag` in a kernel module's image, for a tag that
/// Windows does not write itself: a driver keeps the GUID it tags its data
/// with in a global. `module+offset` when no symbol starts there.
fn tag_owner(session: &Session, tag: &[u8; 16]) -> Option<String> {
    let modules = session.target.kernel_modules().ok()?;
    modules.iter().find_map(|module| {
        let found = session
            .search(module.base_address, tag, module.size as usize)
            .ok()?;
        let hit = *found.matches.first()?;
        Some(
            match session.target.nearest_symbol_current_context(VirtAddr(hit)) {
                Some((owner, name, 0)) => format!("{owner}!{name}"),
                _ => format!("{}+{:#x}", module.short_name, hit - module.base_address.0),
            },
        )
    })
}

/// Show the boot status data (bootstat.dat) the crash dump recorded.
///
/// Whether the last boot succeeded and shut down, the boot IDs of the last
/// successful and abnormal shutdowns, the power transition and power button
/// state, and the feature configuration state, as WinDbg's !blackboxbsd shows
/// them.
#[command(
    names = ["!blackboxbsd"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn blackbox_bsd(session: &Session) -> Result<BootStatus> {
    let data = blackbox_block(session, "!blackboxbsd", &BSD_TAG, "boot status data")?;
    decoded("!blackboxbsd", decode_boot_status(data))
}

impl Render for BootStatus {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_boot_status(self);
    }
}

/// Show the NTFS slow I/O and oplock break timeouts the crash dump recorded.
///
/// Each record shows its type and length; a slow I/O timeout its IRP, SCB,
/// and waiting thread, and an oplock break timeout its reason (the NTFS
/// routine), IRP, SCB, and the owning and breaking processes, as WinDbg's
/// !blackboxntfs shows them.
#[command(
    names = ["!blackboxntfs"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn blackbox_ntfs(session: &Session) -> Result<Vec<NtfsRecord>> {
    let data = blackbox_block(session, "!blackboxntfs", &NTFS_TAG, "NTFS blackbox")?;
    decoded("!blackboxntfs", decode_ntfs(data))
}

impl Render for Vec<NtfsRecord> {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let records = self;
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
    }
}

/// Show the PnP event the crash dump recorded.
///
/// The PnP activity, its time, the event, whether it was in progress, the
/// device's problem code, the veto, and the device instance ID, as WinDbg's
/// !blackboxpnp shows them.
#[command(
    names = ["!blackboxpnp"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn blackbox_pnp(session: &Session) -> Result<PnpBlackbox> {
    let data = blackbox_block(session, "!blackboxpnp", &PNP_TAG, "PnP blackbox")?;
    decoded("!blackboxpnp", decode_pnp(data))
}

impl Render for PnpBlackbox {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!("    PnpActivityId      : {}", self.activity_id);
        outln!("    PnpActivityTime    : {}", self.activity_time);
        outln!("    PnpEventInformation: {}", self.event_information);
        outln!("    PnpEventInProgress : {}", self.event_in_progress);
        outln!("    PnpProblemCode     : {}", self.problem_code);
        outln!("    PnpVetoType        : {}", self.veto_type);
        outln!("    DeviceId           : {}", self.device_id);
        outln!(
            "    VetoString         : {}",
            self.veto_string.as_deref().unwrap_or_default()
        );
    }
}

/// Show what winlogon was doing when the crash dump was written.
#[command(
    names = ["!blackboxwinlogon"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn blackbox_winlogon(session: &Session) -> Result<WinlogonBlackbox> {
    let data = blackbox_block(
        session,
        "!blackboxwinlogon",
        &WINLOGON_TAG,
        "winlogon blackbox",
    )?;
    decoded("!blackboxwinlogon", decode_winlogon(data))
}

impl Render for WinlogonBlackbox {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!("    ThreadName         : {}", self.thread_name);
        outln!("    IsOperationPending : {}", self.is_operation_pending);
    }
}

/// List the PCI functions pci.sys recorded in the crash dump, with their
/// command and status.
///
/// Each function shows its bus, device, and function, its vendor and device
/// IDs and revision, and its command and status registers with their flags as
/// WinDbg's !blackboxpci shows them: i (I/O), m (memory), b (bus master), v
/// (VGA palette snoop), p (parity), s (SERR) for the command, and c
/// (capability list), 6 (66 MHz), P (master data parity error), A (signaled
/// target abort), S (signaled system error) for the status. WinDbg prints the
/// command register's value as the status value; ntoseye prints the status
/// register's.
#[command(
    names = ["!blackboxpci"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn blackbox_pci(session: &Session) -> Result<Vec<PciRecord>> {
    let data = blackbox_block(session, "!blackboxpci", &PCI_TAG, "PCI blackbox")?;
    decoded("!blackboxpci", decode_pci(data))
}

impl Render for Vec<PciRecord> {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for pci in self {
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
    }
}
