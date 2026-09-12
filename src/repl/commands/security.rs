use std::collections::BTreeMap;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::repl::*;
use crate::symbols::glob_matches;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;
use tabled::builder::Builder;

const MAX_SESSION_PROCESSES: usize = 4096;
const MAX_SESSION_DISPLAY: usize = 64;
const MAX_ACE_COUNT: usize = 1024;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

repl_command! {
    cmd_sd;
    names: ["!sd", "sd"],
    usage: "!sd <address> [1]",
    summary: "Decode a SECURITY_DESCRIPTOR and its ACLs.",
    details: "The optional 1 annotates well-known SIDs. Self-relative descriptors and absolute descriptors are both supported; each SID/ACE is decoded independently.",
    completion: [Expression, None],
}

repl_command! {
    cmd_acl;
    names: ["!acl", "acl"],
    usage: "!acl <address>",
    summary: "Decode an ACL and its ACEs.",
    completion: Expression,
}

repl_command! {
    cmd_sid;
    names: ["!sid", "sid"],
    usage: "!sid <address>",
    summary: "Decode a SID in guest memory.",
    completion: Expression,
}

repl_command! {
    cmd_objsd;
    names: ["!objsd", "objsd"],
    usage: "!objsd <object>",
    summary: "Decode the security descriptor referenced by an object header.",
    details: "The OBJECT_HEADER.SecurityDescriptor fast-reference low four bits are masked before decoding.",
    completion: Expression,
}

repl_command! {
    cmd_session;
    names: ["!session", "session"],
    usage: "!session [-s <id>]",
    summary: "List sessions and the processes grouped into each session.",
    details: "Session IDs are read from _EPROCESS.Session and _MM_SESSION_SPACE, with a primary-token fallback when session space is opaque. Use -s -1 for the current session; the process walk is bounded to 4096 entries.",
    completion: [None, Expression],
}

repl_command! {
    cmd_sprocess;
    names: ["!sprocess", "sprocess"],
    usage: "!sprocess [session] [flags] [image]",
    summary: "List processes in a session.",
    details: "The session is signed decimal: -1 and -2 select the current session, and -4 all sessions. Without a session, the attached process's session is selected when known. Flags default to 0 (brief); any non-zero value selects detailed output. The optional image argument is a case-insensitive glob.",
    completion: [Expression, Expression, None],
}

#[derive(Debug, Clone)]
struct SidInfo {
    text: String,
    well_known: Option<&'static str>,
}

fn sid_name(text: &str) -> Option<&'static str> {
    const NAMES: &[(&str, &str)] = &[
        ("S-1-0-0", "SECURITY_NULL_SID"),
        ("S-1-1-0", "Everyone"),
        ("S-1-2-0", "LOCAL"),
        ("S-1-3-0", "CREATOR_OWNER"),
        ("S-1-3-1", "CREATOR_GROUP"),
        ("S-1-5-7", "ANONYMOUS LOGON"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-5-18", "LOCAL SYSTEM"),
        ("S-1-5-19", "LOCAL SERVICE"),
        ("S-1-5-20", "NETWORK SERVICE"),
        ("S-1-5-32", "BUILTIN"),
        ("S-1-5-32-544", "Administrators"),
        ("S-1-5-32-545", "Users"),
        ("S-1-5-32-546", "Guests"),
        ("S-1-5-32-547", "Power Users"),
        ("S-1-5-32-548", "Account Operators"),
        ("S-1-5-32-549", "Server Operators"),
        ("S-1-5-32-550", "Print Operators"),
        ("S-1-5-32-551", "Backup Operators"),
        ("S-1-5-32-552", "Replicator"),
        ("S-1-5-32-554", "Pre-Windows 2000 Compatible Access"),
        ("S-1-5-32-555", "Remote Desktop Users"),
        ("S-1-5-32-556", "Network Configuration Operators"),
        ("S-1-5-32-557", "Incoming Forest Trust Builders"),
        ("S-1-5-32-558", "Performance Monitor Users"),
        ("S-1-5-32-559", "Performance Log Users"),
        ("S-1-5-32-560", "Windows Authorization Access Group"),
        ("S-1-5-32-561", "Terminal Server License Servers"),
        ("S-1-5-32-562", "Distributed COM Users"),
        ("S-1-5-32-568", "IIS_IUSRS"),
        ("S-1-5-32-569", "Cryptographic Operators"),
        ("S-1-5-32-573", "Event Log Readers"),
        ("S-1-5-32-574", "Certificate Service DCOM Access"),
        ("S-1-5-32-575", "RDS Remote Access Servers"),
        ("S-1-5-32-576", "RDS Endpoint Servers"),
        ("S-1-5-32-577", "RDS Management Servers"),
        ("S-1-5-32-578", "Hyper-V Administrators"),
        ("S-1-5-32-579", "Access Control Assistance Operators"),
        ("S-1-5-32-580", "Remote Management Users"),
    ];
    NAMES
        .iter()
        .find(|(sid, _)| *sid == text)
        .map(|(_, name)| *name)
}

fn read_sid_bounded<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    max_len: usize,
) -> Result<SidInfo> {
    if max_len < 8 {
        return Err(Error::DebugInfo(format!(
            "SID at {:#x} has only {max_len} bytes available",
            address.0
        )));
    }
    let mut header = [0u8; 8];
    memory.read_bytes(address, &mut header)?;
    let revision = header[0];
    let count = usize::from(header[1]);
    if revision != 1 || count > 15 {
        return Err(Error::DebugInfo(format!(
            "invalid SID header at {:#x} (revision {}, sub-authorities {})",
            address.0, revision, count
        )));
    }
    let sid_len = 8usize + count * 4;
    if sid_len > max_len {
        return Err(Error::DebugInfo(format!(
            "SID at {:#x} requires {sid_len} bytes, only {max_len} are available",
            address.0
        )));
    }
    let mut authority = 0u64;
    for byte in &header[2..8] {
        authority = (authority << 8) | u64::from(*byte);
    }
    let mut text = format!("S-{revision}-{authority}");
    for index in 0..count {
        let value: u32 = memory.read(address + 8u64 + (index as u64) * 4)?;
        text.push('-');
        text.push_str(&value.to_string());
    }
    let well_known = sid_name(&text);
    Ok(SidInfo { text, well_known })
}

fn read_sid<M: MemoryOps<VirtAddr>>(memory: &M, address: VirtAddr) -> Result<SidInfo> {
    read_sid_bounded(memory, address, usize::MAX)
}

fn ace_type_name(kind: u8) -> &'static str {
    match kind {
        0 => "ACCESS_ALLOWED",
        1 => "ACCESS_DENIED",
        2 => "SYSTEM_AUDIT",
        3 => "SYSTEM_ALARM",
        4 => "ACCESS_ALLOWED_COMPOUND",
        5 => "ACCESS_ALLOWED_OBJECT",
        6 => "ACCESS_DENIED_OBJECT",
        7 => "SYSTEM_AUDIT_OBJECT",
        8 => "SYSTEM_ALARM_OBJECT",
        9 => "ACCESS_ALLOWED_CALLBACK",
        10 => "ACCESS_DENIED_CALLBACK",
        11 => "ACCESS_ALLOWED_CALLBACK_OBJECT",
        12 => "ACCESS_DENIED_CALLBACK_OBJECT",
        13 => "SYSTEM_AUDIT_CALLBACK",
        14 => "SYSTEM_ALARM_CALLBACK",
        15 => "SYSTEM_AUDIT_CALLBACK_OBJECT",
        16 => "SYSTEM_ALARM_CALLBACK_OBJECT",
        17 => "SYSTEM_MANDATORY_LABEL",
        18 => "SYSTEM_RESOURCE_ATTRIBUTE",
        19 => "SYSTEM_SCOPED_POLICY_ID",
        20 => "SYSTEM_PROCESS_TRUST_LABEL",
        21 => "SYSTEM_ACCESS_FILTER",
        _ => "UNKNOWN",
    }
}

fn ace_flags(flags: u8) -> String {
    const FLAGS: &[(u8, &str)] = &[
        (0x01, "OBJECT_INHERIT"),
        (0x02, "CONTAINER_INHERIT"),
        (0x04, "NO_PROPAGATE_INHERIT"),
        (0x08, "INHERIT_ONLY"),
        (0x10, "INHERITED"),
        (0x40, "SUCCESSFUL_ACCESS"),
        (0x80, "FAILED_ACCESS"),
    ];
    let mut names = Vec::new();
    for (bit, name) in FLAGS {
        if flags & bit != 0 {
            names.push(*name);
        }
    }
    if names.is_empty() {
        "-".into()
    } else {
        names.join("|")
    }
}

fn object_ace(kind: u8) -> bool {
    matches!(kind, 5 | 6 | 7 | 8 | 11 | 12 | 15 | 16)
}

fn ace_minimum_size(kind: u8) -> usize {
    if kind == 4 || object_ace(kind) { 12 } else { 8 }
}

#[derive(Debug)]
struct AceInfo {
    kind: u8,
    flags: u8,
    mask: Option<u32>,
    sid: Result<SidInfo>,
}

#[derive(Debug)]
struct AclInfo {
    revision: u8,
    size: u16,
    ace_count: u16,
    aces: Vec<AceInfo>,
    bounded: bool,
    unknown_revision: bool,
}

fn decode_acl<M: MemoryOps<VirtAddr>>(memory: &M, address: VirtAddr) -> Result<AclInfo> {
    let mut header = [0u8; 8];
    memory.read_bytes(address, &mut header)?;
    let revision = header[0];
    let size = u16::from_le_bytes([header[2], header[3]]);
    let ace_count = u16::from_le_bytes([header[4], header[5]]);
    if usize::from(size) < 8 {
        return Err(Error::DebugInfo(format!("invalid ACL size {size:#x}")));
    }
    if !matches!(revision, 2 | 4) {
        return Ok(AclInfo {
            revision,
            size,
            ace_count,
            aces: Vec::new(),
            bounded: false,
            unknown_revision: true,
        });
    }
    let mut offset = 8usize;
    let mut aces = Vec::new();
    let mut bounded = false;
    for _ in 0..usize::from(ace_count).min(MAX_ACE_COUNT) {
        if offset
            .checked_add(4)
            .is_none_or(|end| end > usize::from(size))
        {
            break;
        }
        let ace_address = address + offset as u64;
        let mut ace_header = [0u8; 4];
        if let Err(error) = memory.read_bytes(ace_address, &mut ace_header) {
            aces.push(AceInfo {
                kind: 0xff,
                flags: 0,
                mask: None,
                sid: Err(error),
            });
            break;
        }
        let kind = ace_header[0];
        let flags = ace_header[1];
        let ace_size = usize::from(u16::from_le_bytes([ace_header[2], ace_header[3]]));
        let minimum_size = ace_minimum_size(kind);
        if ace_size < minimum_size
            || offset
                .checked_add(ace_size)
                .is_none_or(|end| end > usize::from(size))
        {
            return Err(Error::DebugInfo(format!(
                "invalid ACE size {ace_size:#x} at ACL offset {offset:#x} (minimum {minimum_size:#x})"
            )));
        }
        let mask = memory.read::<u32>(ace_address + 4u64).ok();
        let sid_offset = if kind == 4 {
            12usize
        } else if object_ace(kind) {
            let object_flags = match memory.read::<u32>(ace_address + 8u64) {
                Ok(value) => value,
                Err(error) => {
                    aces.push(AceInfo {
                        kind,
                        flags,
                        mask,
                        sid: Err(error),
                    });
                    offset += ace_size;
                    continue;
                }
            };
            12usize
                .saturating_add(if object_flags & 1 != 0 { 16 } else { 0 })
                .saturating_add(if object_flags & 2 != 0 { 16 } else { 0 })
        } else {
            8
        };
        let sid = if sid_offset <= ace_size {
            read_sid_bounded(
                memory,
                ace_address + sid_offset as u64,
                ace_size - sid_offset,
            )
        } else {
            Err(Error::DebugInfo(format!(
                "ACE SID offset {sid_offset:#x} exceeds ACE size {ace_size:#x}"
            )))
        };
        aces.push(AceInfo {
            kind,
            flags,
            mask,
            sid,
        });
        offset += ace_size;
    }
    if usize::from(ace_count) > MAX_ACE_COUNT {
        bounded = true;
    }
    Ok(AclInfo {
        revision,
        size,
        ace_count,
        aces,
        bounded,
        unknown_revision: false,
    })
}

fn print_sid(sid: &SidInfo, show_names: bool) -> String {
    match (show_names, sid.well_known) {
        (true, Some(name)) => format!("{} ({name})", sid.text),
        _ => sid.text.clone(),
    }
}

fn print_acl<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: VirtAddr,
    show_names: bool,
    label: &str,
) -> Result<()> {
    let acl = decode_acl(memory, address)?;
    let status = if acl.unknown_revision {
        " (unknown revision; ACEs not decoded)"
    } else if acl.bounded {
        " (bounded)"
    } else {
        ""
    };
    outln!(
        "  {label} {} revision {} size {:#x} ACEs {}{status}",
        ui::addr(address.0),
        acl.revision,
        acl.size,
        acl.ace_count
    );
    for (index, ace) in acl.aces.iter().enumerate() {
        let sid = match &ace.sid {
            Ok(sid) => print_sid(sid, show_names),
            Err(error) => format!("<unavailable: {error}>"),
        };
        outln!(
            "    ACE[{index}] type={} ({:#x}) flags={} ({:#x}) mask={} SID={sid}",
            ace_type_name(ace.kind),
            ace.kind,
            ace_flags(ace.flags),
            ace.flags,
            ace.mask
                .map(|mask| format!("{mask:#010x}"))
                .unwrap_or_else(|| "<unavailable>".into()),
        );
    }
    Ok(())
}

fn control_flags(control: u16) -> String {
    const FLAGS: &[(u16, &str)] = &[
        (0x0001, "SE_OWNER_DEFAULTED"),
        (0x0002, "SE_GROUP_DEFAULTED"),
        (SE_DACL_PRESENT, "SE_DACL_PRESENT"),
        (0x0008, "SE_DACL_DEFAULTED"),
        (SE_SACL_PRESENT, "SE_SACL_PRESENT"),
        (0x0020, "SE_SACL_DEFAULTED"),
        (0x0040, "SE_DACL_TRUSTED"),
        (0x0080, "SE_SERVER_SECURITY"),
        (0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
        (0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
        (0x0400, "SE_DACL_AUTO_INHERITED"),
        (0x0800, "SE_SACL_AUTO_INHERITED"),
        (0x1000, "SE_DACL_PROTECTED"),
        (0x2000, "SE_SACL_PROTECTED"),
        (0x4000, "SE_RM_CONTROL_VALID"),
        (SE_SELF_RELATIVE, "SE_SELF_RELATIVE"),
    ];
    let names: Vec<_> = FLAGS
        .iter()
        .filter(|(bit, _)| control & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "-".into()
    } else {
        names.join("|")
    }
}

fn descriptor_component(raw: u64, base: VirtAddr, self_relative: bool) -> Option<VirtAddr> {
    if raw == 0 {
        None
    } else if self_relative {
        Some(base + (raw as u32 as u64))
    } else {
        Some(VirtAddr(raw))
    }
}

fn print_security_descriptor<M: MemoryOps<VirtAddr>>(
    memory: &M,
    target: &Target,
    dtb: u64,
    address: VirtAddr,
    show_names: bool,
) -> Result<()> {
    let types = target.guest()?.ntoskrnl.types_in(dtb);
    let descriptor = types.struct_at("_SECURITY_DESCRIPTOR", address)?;
    outln!("SECURITY_DESCRIPTOR {}", ui::addr(address.0));
    let revision = descriptor.read_field::<u8>("Revision");
    let control = descriptor.read_field::<u16>("Control");
    match &revision {
        Ok(value) => outln!("  Revision              : {value:#x}"),
        Err(error) => outln!("  Revision              : <unavailable: {error}>"),
    }
    let self_relative = control
        .as_ref()
        .is_ok_and(|value| *value & SE_SELF_RELATIVE != 0);
    match &control {
        Ok(value) => outln!(
            "  Control               : {value:#06x} ({})",
            control_flags(*value)
        ),
        Err(error) => outln!("  Control               : <unavailable: {error}>"),
    }

    if let Ok(value) = revision
        && value != 1
    {
        return Err(Error::DebugInfo(format!(
            "unsupported SECURITY_DESCRIPTOR revision {value:#x}"
        )));
    }
    let relative = if self_relative {
        Some(types.struct_at("_SECURITY_DESCRIPTOR_RELATIVE", address)?)
    } else {
        None
    };

    for (label, field_name) in [("Owner", "Owner"), ("Group", "Group")] {
        let raw = if let Some(relative) = relative.as_ref() {
            relative.read_field::<u32>(field_name).map(u64::from)
        } else {
            descriptor
                .read_field::<VirtAddr>(field_name)
                .map(|value| value.0)
        };
        match raw {
            Err(error) => outln!("  {label:22}: <unavailable: {error}>"),
            Ok(raw) => match descriptor_component(raw, address, self_relative) {
                None => outln!("  {label:22}: NULL"),
                Some(pointer) => match read_sid(memory, pointer) {
                    Ok(sid) => outln!("  {label:22}: {}", print_sid(&sid, show_names)),
                    Err(error) => outln!(
                        "  {label:22}: {} <unavailable: {error}>",
                        ui::addr(pointer.0)
                    ),
                },
            },
        }
    }

    for (label, field_name, bit) in [
        ("DACL", "Dacl", SE_DACL_PRESENT),
        ("SACL", "Sacl", SE_SACL_PRESENT),
    ] {
        let Some(control_value) = control.as_ref().ok().copied() else {
            outln!("  {label:22}: <unavailable: Control could not be read>");
            continue;
        };
        if control_value & bit == 0 {
            outln!("  {label:22}: not present");
            continue;
        }
        let raw = if let Some(relative) = relative.as_ref() {
            relative.read_field::<u32>(field_name).map(u64::from)
        } else {
            descriptor
                .read_field::<VirtAddr>(field_name)
                .map(|value| value.0)
        };
        match raw {
            Err(error) => outln!("  {label:22}: <unavailable: {error}>"),
            Ok(raw) => match descriptor_component(raw, address, self_relative) {
                None => outln!("  {label:22}: NULL (unrestricted)"),
                Some(pointer) => match print_acl(memory, pointer, show_names, label) {
                    Ok(()) => {}
                    Err(error) => outln!(
                        "  {label:22}: {} <unavailable: {error}>",
                        ui::addr(pointer.0)
                    ),
                },
            },
        }
    }
    Ok(())
}

pub(super) fn process_session_id(target: &Target, eprocess: VirtAddr) -> Option<u32> {
    let kernel_dtb = target.kernel_dtb();
    let types = target.guest().ok()?.ntoskrnl.types_in(kernel_dtb);
    let eprocess = types.struct_at("_EPROCESS", eprocess).ok()?;
    if let Some(session) = eprocess
        .read_field::<VirtAddr>("Session")
        .ok()
        .filter(|address| !address.is_zero())
        && let Ok(session) = types.struct_at("_MM_SESSION_SPACE", session)
        && let Ok(id) = session.read_field::<u32>("SessionId")
    {
        return Some(id);
    }

    let token = eprocess
        .read_field::<VirtAddr>("Token")
        .ok()
        .map(|address| VirtAddr(address.0 & !0xf))
        .filter(|address| !address.is_zero())?;
    let token = types.struct_at("_TOKEN", token).ok()?;
    token.read_field::<u32>("SessionId").ok()
}

fn collect_sessions(target: &Target) -> Result<Vec<(ProcessInfo, Option<u64>)>> {
    Ok(target
        .matching_processes(None)?
        .into_iter()
        .take(MAX_SESSION_PROCESSES)
        .map(|process| {
            let session = process_session_id(target, process.eprocess_va).map(u64::from);
            (process, session)
        })
        .collect())
}

#[derive(Debug, Clone, Copy)]
enum SessionSelector {
    Id(u64),
    Current,
    All,
}

fn parse_session_selector(text: &str) -> Option<SessionSelector> {
    let value = match text.parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            error!("invalid session '{text}': expected a signed decimal value");
            return None;
        }
    };
    match value {
        -1 => Some(SessionSelector::Current),
        -2 => Some(SessionSelector::Current),
        -4 => Some(SessionSelector::All),
        value if value >= 0 => Some(SessionSelector::Id(value as u64)),
        _ => {
            error!("invalid session selector {value}; expected a non-negative ID, -1, -2, or -4");
            None
        }
    }
}

fn current_session_id(target: &Target, processes: &[(ProcessInfo, Option<u64>)]) -> Option<u64> {
    target
        .current_process_info
        .as_ref()
        .and_then(|current| {
            processes
                .iter()
                .find(|(process, _)| process.eprocess_va == current.eprocess_va)
                .and_then(|(_, session)| *session)
        })
        .or_else(|| {
            target
                .windows_thread_selection
                .as_ref()
                .and_then(|thread| thread.eprocess)
                .and_then(|eprocess| {
                    processes
                        .iter()
                        .find(|(process, _)| process.eprocess_va == eprocess)
                        .and_then(|(_, session)| *session)
                })
        })
}

fn resolve_session_selector(
    selector: SessionSelector,
    target: &Target,
    processes: &[(ProcessInfo, Option<u64>)],
) -> Result<Option<u64>> {
    match selector {
        SessionSelector::Id(id) => Ok(Some(id)),
        SessionSelector::All => Ok(None),
        SessionSelector::Current => current_session_id(target, processes)
            .map(Some)
            .ok_or_else(|| Error::DebugInfo("current session is unavailable".into())),
    }
}

impl ReplState<'_> {
    fn cmd_sd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty()
            || invocation.argv.len() > 2
            || invocation.arg(1).is_some_and(|flag| flag != "1")
        {
            outln!("{}\n", command_help("!sd"));
            return Ok(());
        }
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help("!sd"));
            return Ok(());
        };
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let show_names = invocation.arg(1) == Some("1");
        let dtb = self.ctx.target.kernel_dtb();
        let memory = match self.ctx.target.current_process() {
            Ok(process) => process.memory(),
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if let Err(error) =
            print_security_descriptor(&memory, &self.ctx.target, dtb, address, show_names)
        {
            error!("{error}");
        }
        Ok(())
    }

    fn cmd_acl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help("!acl"));
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help("!acl"));
            return Ok(());
        }
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let memory = match self.ctx.target.current_process() {
            Ok(process) => process.memory(),
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if let Err(error) = print_acl(&memory, address, false, "ACL") {
            error!("{error}");
        }
        Ok(())
    }

    fn cmd_sid(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help("!sid"));
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help("!sid"));
            return Ok(());
        }
        let address = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let memory = match self.ctx.target.current_process() {
            Ok(process) => process.memory(),
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match read_sid(&memory, address) {
            Ok(sid) => outln!(
                "SID {}{}",
                sid.text,
                sid.well_known
                    .map(|name| format!(" ({name})"))
                    .unwrap_or_default()
            ),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_objsd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help("!objsd"));
            return Ok(());
        };
        if invocation.argv.len() != 1 {
            outln!("{}\n", command_help("!objsd"));
            return Ok(());
        }
        let object = match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let header = match self.ctx.target.inspect_object_header(object) {
            Ok(header) => header,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let dtb = self.ctx.target.kernel_dtb();
        let memory = self.ctx.target.kernel_address_space();
        let object_header = match self.ctx.target.guest().and_then(|guest| {
            guest
                .ntoskrnl
                .types()
                .struct_at("_OBJECT_HEADER", header.header)
        }) {
            Ok(object_header) => object_header,
            Err(error) => {
                error!("_OBJECT_HEADER unavailable: {error}");
                return Ok(());
            }
        };
        let raw = match object_header.read_field::<u64>("SecurityDescriptor") {
            Ok(value) => value,
            Err(error) => {
                error!("_OBJECT_HEADER.SecurityDescriptor unavailable: {error}");
                return Ok(());
            }
        };
        let descriptor = VirtAddr(raw & !0xf);
        outln!(
            "object {} header {} SecurityDescriptor {} (fast-ref {raw:#x})",
            ui::addr(object.0),
            ui::addr(header.header.0),
            ui::addr(descriptor.0)
        );
        if descriptor.is_zero() {
            outln!("security descriptor: NULL");
            return Ok(());
        }
        if let Err(error) =
            print_security_descriptor(&memory, &self.ctx.target, dtb, descriptor, true)
        {
            error!("{error}");
        }
        Ok(())
    }

    fn cmd_session(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut requested = None;
        let mut index = 0;
        while index < invocation.argv.len() {
            if invocation.arg(index) != Some("-s") || requested.is_some() {
                outln!("{}\n", command_help("!session"));
                return Ok(());
            }
            index += 1;
            let Some(text) = invocation.arg(index) else {
                outln!("{}\n", command_help("!session"));
                return Ok(());
            };
            requested = parse_session_selector(text);
            if requested.is_none() {
                return Ok(());
            }
            index += 1;
        }
        let processes = match collect_sessions(&self.ctx.target) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {error}");
                return Ok(());
            }
        };
        let requested = match requested {
            Some(selector) => {
                match resolve_session_selector(selector, &self.ctx.target, &processes) {
                    Ok(session) => session,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
            None => None,
        };
        *self.caches.processes.write().unwrap() = processes
            .iter()
            .map(|(process, _)| (process.name.clone(), process.pid))
            .collect();
        let mut groups: BTreeMap<Option<u64>, Vec<&ProcessInfo>> = BTreeMap::new();
        for (process, session) in &processes {
            if requested.is_none_or(|id| *session == Some(id)) {
                groups.entry(*session).or_default().push(process);
            }
        }
        outln!("sessions: {}", groups.len());
        for (session, processes) in groups {
            match session {
                Some(id) => outln!(
                    "  Session {id}: {} process{}",
                    processes.len(),
                    if processes.len() == 1 { "" } else { "es" }
                ),
                None => outln!(
                    "  Session ?: {} process{}",
                    processes.len(),
                    if processes.len() == 1 { "" } else { "es" }
                ),
            }
            for process in processes.iter().take(MAX_SESSION_DISPLAY) {
                outln!(
                    "    {:>6} {}  EPROCESS {}",
                    process.pid,
                    process.name,
                    ui::addr(process.eprocess_va.0)
                );
            }
            if processes.len() > MAX_SESSION_DISPLAY {
                outln!(
                    "    ... {} additional processes omitted",
                    processes.len() - MAX_SESSION_DISPLAY
                );
            }
        }
        if processes.len() >= MAX_SESSION_PROCESSES {
            outln!("process enumeration bounded at {MAX_SESSION_PROCESSES}");
        }
        Ok(())
    }

    fn cmd_sprocess(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 3 {
            outln!("{}\n", command_help("!sprocess"));
            return Ok(());
        }
        let selector = match invocation.arg(0) {
            Some(text) => match parse_session_selector(text) {
                Some(selector) => Some(selector),
                None => return Ok(()),
            },
            None => None,
        };
        let flags = match invocation.arg(1) {
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(flags) => flags.0,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => 0,
        };
        let image_filter = invocation.arg(2);
        let processes = match collect_sessions(&self.ctx.target) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {error}");
                return Ok(());
            }
        };
        let requested = match selector {
            Some(selector) => {
                match resolve_session_selector(selector, &self.ctx.target, &processes) {
                    Ok(session) => session,
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
            None => current_session_id(&self.ctx.target, &processes),
        };
        *self.caches.processes.write().unwrap() = processes
            .iter()
            .map(|(process, _)| (process.name.clone(), process.pid))
            .collect();
        let selected: Vec<_> = processes
            .iter()
            .filter(|(process, session)| {
                requested.is_none_or(|id| *session == Some(id))
                    && image_filter.is_none_or(|pattern| glob_matches(pattern, &process.name, true))
            })
            .collect();
        outln!(
            "{}{} process{}",
            requested
                .map(|id| format!("session {id}: "))
                .unwrap_or_default(),
            selected.len(),
            if selected.len() == 1 { "" } else { "es" }
        );
        let brief = flags == 0;
        let mut builder = Builder::default();
        if brief {
            builder.push_record(["PID", "Name"]);
            for (process, _) in &selected {
                builder.push_record([process.pid.to_string(), process.name.clone()]);
            }
        } else {
            builder.push_record(["PID", "Name", "EPROCESS", "DTB", "Session"]);
            for (process, session) in &selected {
                builder.push_record([
                    process.pid.to_string(),
                    process.name.clone(),
                    ui::addr(process.eprocess_va.0),
                    ui::addr(process.dtb),
                    session
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "?".into()),
                ]);
            }
        }
        if !selected.is_empty() {
            print_padded_table(builder);
        }
        Ok(())
    }
}
