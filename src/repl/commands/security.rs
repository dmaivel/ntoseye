use tabled::builder::Builder;

use ntoseye_macros::{command, grammar};

use crate::error::Result;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::DiagnosticValue;
use crate::target::security::{
    self, Acl, ObjectSecurity, SecurityDescriptor, SessionProcesses, Sessions, Sid,
};
use crate::types::VirtAddr;
use crate::ui;

use super::diagnostics::{diagnostic_cell, diagnostic_hex};

const MAX_SESSION_DISPLAY: usize = 64;

/// The address of a command that takes exactly one expression: any other
/// word count prints the help.
#[grammar(usage = "<{}>", complete = [Expression])]
fn single_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    if cursor.remaining() != 1 {
        return Err(ArgError::Missing);
    }
    let text = cursor.word().ok_or(ArgError::Missing)?;
    cx.eval(&text)
}

/// `!sd`'s optional `1` (the second word), checked before the address is
/// evaluated: one or two words, and the second one must be `1`.
#[grammar(usage = "")]
fn sd_annotate(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    if !(1..=2).contains(&cursor.remaining()) {
        return Err(ArgError::Missing);
    }
    match cursor.word_at(1).as_deref() {
        None => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(ArgError::Missing),
    }
}

/// A session id: a signed decimal number.
fn session_id(text: &str) -> std::result::Result<i64, ArgError> {
    text.parse::<i64>().map_err(|_| {
        ArgError::Message(format!(
            "invalid session '{text}': expected a signed decimal value"
        ))
    })
}

/// `!session`'s `-s <id>`; anything else prints the help.
#[grammar(usage = "[-s <id>]", complete = [None, Expression])]
fn session_switch(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<i64>, ArgError> {
    if cursor.remaining() == 0 {
        return Ok(None);
    }
    if cursor.word().as_deref() != Some("-s") {
        return Err(ArgError::Missing);
    }
    let text = cursor.word().ok_or(ArgError::Missing)?;
    let session = session_id(&text)?;
    if cursor.remaining() != 0 {
        return Err(ArgError::Missing);
    }
    Ok(Some(session))
}

/// `!sprocess`'s session: at most three words, the first a session id.
#[grammar(usage = "[{}]", complete = [Expression])]
fn sprocess_session(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<i64>, ArgError> {
    if cursor.remaining() > 3 {
        return Err(ArgError::Missing);
    }
    cursor.word().map(|text| session_id(&text)).transpose()
}

/// Decode a SECURITY_DESCRIPTOR and its ACLs.
///
/// Decodes a self-relative or absolute security descriptor, and decodes each
/// SID and each ACE separately. The optional 1 adds the names of well-known
/// SIDs.
#[command(
    names = ["!sd", "sd"],
    category = "security",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "security_descriptor",
)]
fn sd(
    session: &Session,
    #[arg(render, parse = sd_annotate)] annotate_well_known: bool,
    #[arg(parse = single_address_word)] address: VirtAddr,
) -> Result<SecurityDescriptor> {
    session.target.inspect_security_descriptor(address)
}

/// The next word as an address (after [`sd_annotate`] checked the line).
#[grammar(usage = "<address> [1]", complete = [Expression, None])]
fn single_address_word(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let text = cursor.word().ok_or(ArgError::Missing)?;
    cx.eval(&text)
}

impl Render<bool> for SecurityDescriptor {
    fn render(&self, _: &mut ReplState<'_>, annotate_well_known: bool) {
        print_security_descriptor(self, annotate_well_known);
    }
}

/// Decode an ACL and its ACEs.
#[command(
    names = ["!acl", "acl"],
    category = "security",
    kind = Query,
    python = Inspect,
)]
fn acl(session: &Session, #[arg(parse = single_address)] address: VirtAddr) -> Result<Acl> {
    session.target.inspect_acl(address)
}

impl Render for Acl {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_acl(self, "ACL", false);
    }
}

/// Decode a SID in guest memory.
#[command(
    names = ["!sid", "sid"],
    category = "security",
    kind = Query,
    python = Inspect,
)]
fn sid(session: &Session, #[arg(parse = single_address)] address: VirtAddr) -> Result<Sid> {
    session.target.inspect_sid(address)
}

impl Render for Sid {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        outln!(
            "SID {}{}",
            self.sid,
            self.well_known
                .as_deref()
                .map(|name| format!(" ({name})"))
                .unwrap_or_default()
        );
    }
}

/// Decode the security descriptor that an object header references.
///
/// The command masks the low four bits of the OBJECT_HEADER.SecurityDescriptor
/// fast reference before it decodes the descriptor.
#[command(
    names = ["!objsd", "objsd"],
    category = "security",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "object_security",
)]
fn objsd(
    session: &Session,
    #[arg(parse = single_address)] object: VirtAddr,
) -> Result<ObjectSecurity> {
    session.target.inspect_object_security(object)
}

impl Render for ObjectSecurity {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_object_security(self);
    }
}

/// List the sessions and the processes in each session.
///
/// The command reads session IDs from _EPROCESS.Session and
/// _MM_SESSION_SPACE, or from the primary token if session space is opaque.
/// Use -s -1 for the current session. The process walk stops at 4096 entries.
#[command(
    names = ["!session", "session"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "sessions",
)]
fn session(
    state: &Session,
    #[arg(parse = session_switch, positional)] session: Option<i64>,
) -> Result<Sessions> {
    state.target.sessions(session)
}

impl Render for Sessions {
    fn render(&self, repl: &mut ReplState<'_>, _: ()) {
        *repl.caches.processes.write().unwrap() = self
            .sessions
            .iter()
            .flat_map(|session| &session.processes)
            .map(|process| (process.name.clone(), process.pid))
            .collect();
        print_sessions(self);
    }
}

/// List the processes in a session.
///
/// The session is a signed decimal number. -1 and -2 select the current
/// session, and -4 selects all sessions. If you do not give a session, the
/// command uses the session of the attached process, if it is known. Flags
/// default to 0 (brief output), and any non-zero value selects detailed
/// output. The optional image argument is a glob that ignores case.
#[command(
    names = ["!sprocess", "sprocess"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "session_processes",
)]
fn sprocess(
    state: &Session,
    #[arg(parse = sprocess_session, positional)] session: Option<i64>,
    #[arg(render, default = 0)] flags: u64,
    image: Option<String>,
) -> Result<SessionProcesses> {
    state.target.session_processes(session, image.as_deref())
}

impl Render<u64> for SessionProcesses {
    fn render(&self, repl: &mut ReplState<'_>, flags: u64) {
        *repl.caches.processes.write().unwrap() = self
            .processes
            .iter()
            .map(|row| (row.process.name.clone(), row.process.pid))
            .collect();
        print_session_processes(self, flags != 0);
    }
}

fn sid_text(sid: &Sid, annotate_well_known: bool) -> String {
    if annotate_well_known && let Some(name) = sid.well_known.as_deref() {
        return format!("{} ({name})", sid.sid);
    }
    sid.sid.clone()
}

fn print_sid_diagnostic(value: &DiagnosticValue<Sid>, annotate_well_known: bool) -> String {
    match value {
        DiagnosticValue::Available(sid) => sid_text(sid, annotate_well_known),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn print_acl(detail: &Acl, label: &str, annotate_well_known: bool) {
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
    value: &DiagnosticValue<Option<Acl>>,
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
    value: &DiagnosticValue<Option<Sid>>,
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

fn print_security_descriptor(detail: &SecurityDescriptor, annotate_well_known: bool) {
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

fn print_object_security(detail: &ObjectSecurity) {
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

fn print_session(detail: &security::Session) {
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
            ui::addr(process.eprocess.0)
        );
    }
    if detail.processes.len() > MAX_SESSION_DISPLAY {
        outln!(
            "    ... {} additional processes omitted",
            detail.processes.len() - MAX_SESSION_DISPLAY
        );
    }
}

fn print_sessions(detail: &Sessions) {
    outln!("sessions: {}", detail.sessions.len());
    for session in &detail.sessions {
        print_session(session);
    }
    if detail.truncated {
        outln!("process enumeration bounded at 4096");
    }
}

fn print_session_processes(detail: &SessionProcesses, detailed: bool) {
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
    if detailed {
        builder.push_record(["PID", "Name", "EPROCESS", "DTB", "Session"]);
        for row in &detail.processes {
            builder.push_record([
                row.process.pid.to_string(),
                row.process.name.clone(),
                ui::addr(row.process.eprocess.0),
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
