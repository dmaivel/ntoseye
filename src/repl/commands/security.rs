use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::Target;
use crate::target::security::{
    AclDetail, ObjectSecurityDetail, SecurityDescriptorDetail, SessionDetail,
    SessionProcessesDetail, SessionsDetail, SidDetail,
    process_session_id as target_process_session_id,
};
use crate::types::VirtAddr;
use crate::ui;

const MAX_SESSION_DISPLAY: usize = 64;

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

fn diagnostic_cell<T: Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_hex<T>(value: &DiagnosticValue<T>) -> String
where
    T: Copy + Into<u64>,
{
    match value {
        DiagnosticValue::Available(value) => format!("{:#x}", (*value).into()),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn sid_text(sid: &SidDetail, annotate_well_known: bool) -> String {
    if annotate_well_known && let Some(name) = sid.well_known.as_deref() {
        return format!("{} ({name})", sid.sid);
    }
    sid.sid.clone()
}

fn print_sid_diagnostic(value: &DiagnosticValue<SidDetail>, annotate_well_known: bool) -> String {
    match value {
        DiagnosticValue::Available(sid) => sid_text(sid, annotate_well_known),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn print_acl(detail: &AclDetail, label: &str, annotate_well_known: bool) {
    let status = if detail.unknown_revision {
        " (unknown revision; ACEs not decoded)"
    } else if detail.bounded {
        " (bounded)"
    } else {
        ""
    };
    outln!(
        "  {label} {} revision {} size {:#x} ACEs {}{status}",
        ui::addr(detail.address.0),
        detail.revision,
        detail.size,
        detail.ace_count
    );
    for ace in &detail.aces {
        outln!(
            "    ACE[{}] type={} ({:#x}) flags={} ({:#x}) mask={} SID={}",
            ace.index,
            ace.type_name,
            ace.ace_type,
            ace.flag_names,
            ace.flags,
            diagnostic_hex(&ace.access_mask),
            print_sid_diagnostic(&ace.sid, annotate_well_known),
        );
    }
}

fn print_descriptor_component(
    label: &str,
    value: &DiagnosticValue<Option<AclDetail>>,
    control: &DiagnosticValue<u16>,
    bit: u16,
    annotate_well_known: bool,
) {
    let Some(control) = (match control {
        DiagnosticValue::Available(value) => Some(*value),
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:22}: <unavailable: Control could not be read: {error}>");
            None
        }
    }) else {
        return;
    };
    if control & bit == 0 {
        outln!("  {label:22}: not present");
        return;
    }
    match value {
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:22}: <unavailable: {error}>");
        }
        DiagnosticValue::Available(None) => {
            outln!("  {label:22}: NULL (unrestricted)");
        }
        DiagnosticValue::Available(Some(acl)) => {
            print_acl(acl, label, annotate_well_known);
        }
    }
}

fn print_sid_component(
    label: &str,
    value: &DiagnosticValue<Option<SidDetail>>,
    annotate_well_known: bool,
) {
    match value {
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:22}: <unavailable: {error}>");
        }
        DiagnosticValue::Available(None) => outln!("  {label:22}: NULL"),
        DiagnosticValue::Available(Some(sid)) => {
            outln!("  {label:22}: {}", sid_text(sid, annotate_well_known));
        }
    }
}

fn print_security_descriptor(detail: &SecurityDescriptorDetail, annotate_well_known: bool) {
    outln!("SECURITY_DESCRIPTOR {}", ui::addr(detail.address.0));
    outln!(
        "  Revision              : {}",
        diagnostic_hex(&detail.revision)
    );
    match &detail.control {
        DiagnosticValue::Available(control) => outln!(
            "  Control               : {control:#06x} ({})",
            diagnostic_cell(&detail.control_names)
        ),
        DiagnosticValue::Unavailable(error) => {
            outln!("  Control               : <unavailable: {error}>");
        }
    }
    print_sid_component("Owner", &detail.owner, annotate_well_known);
    print_sid_component("Group", &detail.group, annotate_well_known);
    print_descriptor_component(
        "DACL",
        &detail.dacl,
        &detail.control,
        0x0004,
        annotate_well_known,
    );
    print_descriptor_component(
        "SACL",
        &detail.sacl,
        &detail.control,
        0x0010,
        annotate_well_known,
    );
    if detail.unsupported_revision
        && let DiagnosticValue::Available(revision) = &detail.revision
    {
        error!("unsupported SECURITY_DESCRIPTOR revision {revision:#x}");
    }
}

fn print_object_security(detail: &ObjectSecurityDetail) {
    outln!(
        "object {} header {} SecurityDescriptor {} (fast-ref {:#x})",
        ui::addr(detail.object.0),
        ui::addr(detail.header.0),
        ui::addr(detail.descriptor_address.0),
        detail.fast_reference
    );
    match &detail.descriptor {
        Some(descriptor) => print_security_descriptor(descriptor, true),
        None => outln!("security descriptor: NULL"),
    }
}

fn print_session(detail: &SessionDetail) {
    match detail.id {
        Some(id) => outln!(
            "  Session {id}: {} process{}",
            detail.processes.len(),
            if detail.processes.len() == 1 {
                ""
            } else {
                "es"
            }
        ),
        None => outln!(
            "  Session ?: {} process{}",
            detail.processes.len(),
            if detail.processes.len() == 1 {
                ""
            } else {
                "es"
            }
        ),
    }
    for process in detail.processes.iter().take(MAX_SESSION_DISPLAY) {
        outln!(
            "    {:>6} {}  EPROCESS {}",
            process.pid,
            process.name,
            ui::addr(process.eprocess_va.0)
        );
    }
    if detail.processes.len() > MAX_SESSION_DISPLAY {
        outln!(
            "    ... {} additional processes omitted",
            detail.processes.len() - MAX_SESSION_DISPLAY
        );
    }
}

fn print_sessions(detail: &SessionsDetail) {
    outln!("sessions: {}", detail.sessions.len());
    for session in &detail.sessions {
        print_session(session);
    }
    if detail.truncated {
        outln!("process enumeration bounded at 4096");
    }
}

fn print_session_processes(detail: &SessionProcessesDetail) {
    outln!(
        "{}{} process{}",
        detail
            .selected_session
            .map(|id| format!("session {id}: "))
            .unwrap_or_default(),
        detail.process_count,
        if detail.process_count == 1 { "" } else { "es" }
    );
    let mut builder = Builder::default();
    if detail.detailed {
        builder.push_record(["PID", "Name", "EPROCESS", "DTB", "Session"]);
        for row in &detail.processes {
            builder.push_record([
                row.process.pid.to_string(),
                row.process.name.clone(),
                ui::addr(row.process.eprocess_va.0),
                ui::addr(row.process.dtb),
                row.session
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "?".into()),
            ]);
        }
    } else {
        builder.push_record(["PID", "Name"]);
        for row in &detail.processes {
            builder.push_record([row.process.pid.to_string(), row.process.name.clone()]);
        }
    }
    if !detail.processes.is_empty() {
        print_padded_table(builder);
    }
    if detail.truncated {
        outln!("process enumeration bounded at 4096");
    }
}

fn parse_session_id(text: &str) -> Option<i64> {
    match text.parse::<i64>() {
        Ok(value) => Some(value),
        Err(_) => {
            error!("invalid session '{text}': expected a signed decimal value");
            None
        }
    }
}

/// Shared by the legacy process command while session inspection migrates to
/// the structured target API.
pub fn process_session_id(target: &Target, eprocess: VirtAddr) -> Option<u32> {
    target_process_session_id(target, eprocess)
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
        let annotate_well_known = invocation.arg(1) == Some("1");
        match self
            .ctx
            .target
            .inspect_security_descriptor(address, annotate_well_known)
        {
            Ok(detail) => print_security_descriptor(&detail, annotate_well_known),
            Err(error) => error!("{error}"),
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
        match self.ctx.target.inspect_acl(address) {
            Ok(detail) => print_acl(&detail, "ACL", false),
            Err(error) => error!("{error}"),
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
        match self.ctx.target.inspect_sid(address) {
            Ok(sid) => outln!(
                "SID {}{}",
                sid.sid,
                sid.well_known
                    .as_deref()
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
        match self.ctx.target.inspect_object_security(object) {
            Ok(detail) => print_object_security(&detail),
            Err(error) => error!("{error}"),
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
            requested = parse_session_id(text);
            if requested.is_none() {
                return Ok(());
            }
            index += 1;
        }
        match self.ctx.target.sessions(requested) {
            Ok(detail) => {
                let mut processes = Vec::new();
                for session in &detail.sessions {
                    processes.extend(
                        session
                            .processes
                            .iter()
                            .map(|process| (process.name.clone(), process.pid)),
                    );
                }
                *self.caches.processes.write().unwrap() = processes.into_iter().collect();
                print_sessions(&detail);
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_sprocess(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 3 {
            outln!("{}\n", command_help("!sprocess"));
            return Ok(());
        }
        let selector = match invocation.arg(0) {
            Some(text) => match parse_session_id(text) {
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
        match self
            .ctx
            .target
            .session_processes(selector, flags != 0, image_filter)
        {
            Ok(detail) => {
                *self.caches.processes.write().unwrap() = detail
                    .processes
                    .iter()
                    .map(|row| (row.process.name.clone(), row.process.pid))
                    .collect();
                print_session_processes(&detail);
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}
