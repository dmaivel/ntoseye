use tabled::builder::Builder;
use tabled::settings::{Padding, Style};

use ntoseye_macros::{command, grammar};

use crate::base::diagnostics::print_warning;
use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::security::{
    self, Acl, ObjectSecurity, SecurityDescriptor, SessionProcesses, Sessions, Sid,
};
use crate::session::Session;

const MAX_SESSION_DISPLAY: usize = 64;

/// What `!session` and `!sprocess` say when the process walk hit its bound.
const TRUNCATED_NOTE: &str =
    "the process walk stopped at 4096 processes; later ones are not listed";

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

/// `!sd`'s and `!acl`'s optional `1` (the second word), checked before the address is
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
///
/// The optional 1 adds the names of well-known SIDs.
#[command(
    names = ["!acl", "acl"],
    category = "security",
    kind = Query,
    target = Nt,
    python = Inspect,
)]
fn acl(
    session: &Session,
    #[arg(render, parse = sd_annotate)] annotate_well_known: bool,
    #[arg(parse = single_address_word)] address: VirtAddr,
) -> Result<Acl> {
    session.target.inspect_acl(address)
}

impl Render<bool> for Acl {
    fn render(&self, _: &mut ReplState<'_>, annotate_well_known: bool) {
        let mut notes = Vec::new();
        outln!("ACL {}", ui::addr(self.address.0));
        outln!("  {}", acl_summary(self));
        print_aces(self, annotate_well_known, "  ", &mut notes);
        print_notes(&notes);
    }
}

/// Decode a SID in guest memory.
#[command(
    names = ["!sid", "sid"],
    category = "security",
    kind = Query,
    target = Nt,
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

/// A value that may not have been read: `None` when it was not, with the
/// reason added to `notes` once, so the block shows `-` in the field and
/// reports each reason after its fields instead of in every cell.
fn available<'a, T>(
    value: &'a DiagnosticValue<T>,
    what: &str,
    notes: &mut Vec<String>,
) -> Option<&'a T> {
    match value {
        DiagnosticValue::Available(value) => Some(value),
        DiagnosticValue::Unavailable(error) => {
            let note = format!("{what} unavailable: {error}");
            if !notes.contains(&note) {
                notes.push(note);
            }
            None
        }
    }
}

/// The reasons a block's fields show `-`, as one warning.
fn print_notes(notes: &[String]) {
    if !notes.is_empty() {
        print_warning(notes.join("; "));
    }
}

/// Flag names as the data layer joins them (`A|B`), spaced as every
/// command's flag sets are (`A | B`).
fn spaced_flags(names: &str) -> String {
    names.replace('|', " | ")
}

/// An ACL's header fields on one line: revision, size and ACE count.
fn acl_summary(detail: &Acl) -> String {
    let status = if detail.unknown_revision {
        " (unknown revision, so the ACEs are not decoded)"
    } else if detail.bounded {
        " (bounded)"
    } else {
        ""
    };
    format!(
        "revision {}  size {:#x}  ACEs {}{status}",
        detail.revision, detail.size, detail.ace_count
    )
}

/// The ACEs as a table indented by `indent`: print_padded_table cannot
/// indent, and the ACEs sit inside their descriptor's or ACL's block.
fn print_aces(detail: &Acl, annotate_well_known: bool, indent: &str, notes: &mut Vec<String>) {
    if detail.aces.is_empty() {
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["ACE", "Type", "Flags", "Mask", "SID"]);
    for ace in &detail.aces {
        let what = format!("ACE {}", ace.index);
        builder.push_record([
            ace.index.to_string(),
            format!("{} ({:#x})", ace.type_name, ace.ace_type),
            // An ACE without inheritance or audit flags shows its value alone.
            if ace.flags == 0 {
                format!("{:#x}", ace.flags)
            } else {
                format!("{:#x} ({})", ace.flags, spaced_flags(&ace.flag_names))
            },
            available(&ace.access_mask, &format!("{what} mask"), notes)
                .map_or_else(|| "-".to_string(), |mask| format!("{mask:#x}")),
            available(&ace.sid, &format!("{what} SID"), notes)
                .map_or_else(|| "-".to_string(), |sid| sid_text(sid, annotate_well_known)),
        ]);
    }
    let mut table = builder.build();
    table.with(Style::empty()).with(Padding::new(0, 2, 0, 0));
    for line in table.to_string().lines() {
        outln!("{indent}{}", line.trim_end());
    }
}

fn print_descriptor_component(
    label: &str,
    value: &DiagnosticValue<Option<Acl>>,
    control: &DiagnosticValue<u16>,
    bit: u16,
    null_meaning: &str,
    annotate_well_known: bool,
    notes: &mut Vec<String>,
) {
    // Without Control, whether the ACL is present is unknown; the Control
    // field's note already says why.
    let Some(control) = available(control, "Control", notes) else {
        outln!("  {label:8} : -");
        return;
    };
    if control & bit == 0 {
        outln!("  {label:8} : not present");
        return;
    }
    match available(value, label, notes) {
        None => outln!("  {label:8} : -"),
        Some(None) => {
            outln!("  {label:8} : - ({null_meaning})");
        }
        Some(Some(acl)) => {
            outln!(
                "  {label:8} : {}  {}",
                ui::addr(acl.address.0),
                acl_summary(acl)
            );
            print_aces(acl, annotate_well_known, "    ", notes);
        }
    }
}

fn print_sid_component(
    label: &str,
    value: &DiagnosticValue<Option<Sid>>,
    annotate_well_known: bool,
    notes: &mut Vec<String>,
) {
    match available(value, label, notes) {
        None | Some(None) => outln!("  {label:8} : -"),
        Some(Some(sid)) => {
            outln!("  {label:8} : {}", sid_text(sid, annotate_well_known));
        }
    }
}

fn print_security_descriptor(detail: &SecurityDescriptor, annotate_well_known: bool) {
    let mut notes = Vec::new();
    outln!("SECURITY_DESCRIPTOR {}", ui::addr(detail.address.0));
    outln!(
        "  Revision : {}",
        available(&detail.revision, "Revision", &mut notes)
            .map_or_else(|| "-".to_string(), |revision| format!("{revision:#x}"))
    );
    let control = available(&detail.control, "Control", &mut notes).copied();
    let control_names =
        control.and_then(|_| available(&detail.control_names, "Control", &mut notes).cloned());
    match (control, control_names) {
        (Some(control), Some(names)) if names != "-" && !names.is_empty() => {
            outln!("  Control  : {control:#06x} ({})", spaced_flags(&names));
        }
        (Some(control), _) => outln!("  Control  : {control:#06x}"),
        (None, _) => outln!("  Control  : -"),
    }
    print_sid_component("Owner", &detail.owner, annotate_well_known, &mut notes);
    print_sid_component("Group", &detail.group, annotate_well_known, &mut notes);
    print_descriptor_component(
        "DACL",
        &detail.dacl,
        &detail.control,
        0x0004,
        "a NULL DACL grants everyone full access",
        annotate_well_known,
        &mut notes,
    );
    print_descriptor_component(
        "SACL",
        &detail.sacl,
        &detail.control,
        0x0010,
        "a NULL SACL audits nothing",
        annotate_well_known,
        &mut notes,
    );
    print_notes(&notes);
    if detail.unsupported_revision
        && let DiagnosticValue::Available(revision) = &detail.revision
    {
        error!("unsupported SECURITY_DESCRIPTOR revision {revision:#x}");
    }
}

fn print_object_security(detail: &ObjectSecurity) {
    outln!("object {}", ui::addr(detail.object.0));
    outln!("  header               {}", ui::addr(detail.header.0));
    match &detail.descriptor {
        Some(_) => outln!(
            "  security descriptor  {} (fast reference {:#x})",
            ui::addr(detail.descriptor_address.0),
            detail.fast_reference
        ),
        None => outln!("  security descriptor  -"),
    }
    if let Some(descriptor) = &detail.descriptor {
        outln!();
        print_security_descriptor(descriptor, true);
    }
}

fn print_session(detail: &security::Session) {
    // Processes outside every session (System, Registry, smss) group under
    // no ID, as WinDbg's "none".
    let id = detail
        .id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "none".to_string());
    let shown = if detail.processes.len() > MAX_SESSION_DISPLAY {
        format!(" (the first {MAX_SESSION_DISPLAY}; !sprocess {id} lists them all)")
    } else {
        String::new()
    };
    outln!(
        "session {id}: {} process{}{shown}",
        detail.processes.len(),
        if detail.processes.len() == 1 {
            ""
        } else {
            "es"
        }
    );
    if detail.processes.is_empty() {
        outln!();
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["PID", "Name", "EPROCESS"]);
    for process in detail.processes.iter().take(MAX_SESSION_DISPLAY) {
        builder.push_record([
            process.pid.to_string(),
            process.name.clone(),
            ui::addr(process.eprocess.0),
        ]);
    }
    print_padded_table(builder);
}

fn print_sessions(detail: &Sessions) {
    for session in &detail.sessions {
        print_session(session);
    }
    if detail.truncated {
        outln!("{}", ui::muted(TRUNCATED_NOTE));
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
                    .unwrap_or_else(|| "-".into()),
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
        outln!("{}", ui::muted(TRUNCATED_NOTE));
    }
}
