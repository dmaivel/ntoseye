use std::fmt::Display;

use tabled::builder::Builder;

use crate::base::error::{Error, Result};
use crate::base::ntstatus::ntstatus_name;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::mm::SystemMemorySummary;
use crate::nt::target::object::{
    ExecutiveResource, FileObject, HandleEntry, HandleTable, MAX_RESOURCES,
    RESOURCE_OWNED_EXCLUSIVE, ResourceList, ResourceOwner,
};
use crate::nt::target::security::Token;
use crate::nt::target::usermode::address::human_size;
use crate::nt::target::usermode::handles::{
    handle_attribute_names, handle_type_counts, handle_type_label,
};
use crate::nt::target::{DiagnosticValue, ListTermination, TargetKind};
use crate::nt::userdump::{HandleObjectInfo, UserHandle};
use crate::session::Session;
use ntoseye_macros::{command, grammar};

/// Show the system memory-use counters and the counters of a limited number
/// of processes.
///
/// The command uses validated memory-manager globals, KDBG fields, or
/// recognized public getter code, and EPROCESS.Vm counters. It does not scan
/// physical memory, and it does not walk all VADs.
#[command(
    names = ["!memusage"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn memusage(
    session: &Session,
    #[arg(default = 64)] process_limit: u64,
) -> Result<SystemMemorySummary> {
    session.target.memory_use_summary(process_limit as usize)
}

impl Render for SystemMemorySummary {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_memory_counters(self);
        print_process_memory(self);
    }
}

/// The fields of one block that could not be read, and why. Each such field
/// shows `-`; the block ends with one muted note naming them, the fields
/// that failed for the same reason together.
#[derive(Default)]
pub struct UnavailableNotes {
    reasons: Vec<(String, Vec<String>)>,
}

impl UnavailableNotes {
    /// Record that `label` could not be read, and return its `-`.
    pub fn missing(&mut self, label: &str, reason: &str) -> String {
        match self.reasons.iter_mut().find(|(known, _)| known == reason) {
            Some((_, labels)) => labels.push(label.to_string()),
            None => self
                .reasons
                .push((reason.to_string(), vec![label.to_string()])),
        }
        "-".to_string()
    }

    /// A value as `Display` shows it, or `-`.
    pub fn value<T: Display>(&mut self, label: &str, value: &DiagnosticValue<T>) -> String {
        match value {
            DiagnosticValue::Available(value) => value.to_string(),
            DiagnosticValue::Unavailable(error) => self.missing(label, error),
        }
    }

    /// A count or size in `0x` hex, or `-`.
    pub fn hex<T: Copy + Into<u64>>(&mut self, label: &str, value: &DiagnosticValue<T>) -> String {
        match value {
            DiagnosticValue::Available(value) => format!("{:#x}", (*value).into()),
            DiagnosticValue::Unavailable(error) => self.missing(label, error),
        }
    }

    /// A pointer, `-` when it is null, or `-` when it could not be read.
    pub fn pointer(&mut self, label: &str, value: &DiagnosticValue<VirtAddr>) -> String {
        match value {
            DiagnosticValue::Available(value) => ui::addr_opt(*value),
            DiagnosticValue::Unavailable(error) => self.missing(label, error),
        }
    }

    /// A yes/no flag, or `-`.
    pub fn yes_no(&mut self, label: &str, value: &DiagnosticValue<bool>) -> String {
        match value {
            DiagnosticValue::Available(value) => yes_no(*value).to_string(),
            DiagnosticValue::Unavailable(error) => self.missing(label, error),
        }
    }

    /// The block's note, `indent` in: `unavailable: PageColor: <reason>`.
    pub fn print(&self, indent: &str) {
        for (reason, labels) in &self.reasons {
            outln!(
                "{indent}{}",
                ui::muted(&format!("unavailable: {}: {reason}", labels.join(", ")))
            );
        }
    }
}

pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// A memory counter as a human-readable size in binary units.
fn size_cell(notes: &mut UnavailableNotes, label: &str, bytes: &DiagnosticValue<u64>) -> String {
    match bytes {
        DiagnosticValue::Available(bytes) => human_size(*bytes),
        DiagnosticValue::Unavailable(error) => notes.missing(label, error),
    }
}

/// The system-wide counters of a memory-use summary.
pub fn print_memory_counters(summary: &SystemMemorySummary) {
    print_section("system memory");
    let mut notes = UnavailableNotes::default();
    for (label, metric) in [
        ("physical pages", &summary.physical_pages),
        ("available pages", &summary.available_pages),
        ("committed pages", &summary.committed_pages),
        ("commit limit pages", &summary.commit_limit_pages),
        ("paged pool pages", &summary.paged_pool_pages),
        ("nonpaged pool bytes", &summary.nonpaged_pool_bytes),
    ] {
        outln!("  {label:<19}  {}", notes.value(label, &metric.value));
    }
    notes.print("  ");
}

/// The per-process rows of a memory-use summary, last in the output: the
/// table ends with a blank line of its own.
pub fn print_process_memory(summary: &SystemMemorySummary) {
    let mut notes = UnavailableNotes::default();
    if !summary.processes.is_empty() {
        print_section("processes");
        let mut builder = Builder::default();
        builder.push_record([
            "PID",
            "Name",
            "Virtual",
            "Working set",
            "Pagefile",
            "Private",
        ]);
        for process in &summary.processes {
            builder.push_record([
                process.process.pid.to_string(),
                process.process.name.clone(),
                size_cell(&mut notes, "virtual", &process.virtual_size),
                size_cell(&mut notes, "working set", &process.working_set_size),
                size_cell(&mut notes, "pagefile", &process.pagefile_usage),
                size_cell(&mut notes, "private", &process.private_usage),
            ]);
        }
        print_padded_table(builder);
    }
    notes.print("");
    if summary.truncated {
        outln!(
            "{}",
            ui::muted(&format!(
                "{} of {} processes shown",
                summary.processes.len(),
                summary.process_count
            ))
        );
    }
}

/// `!handle`'s flags on a user-mode minidump, as WinDbg's user-mode flags:
/// the handle's type; its access, attributes, and counts; its object's
/// name; and object-specific information, which a minidump records for
/// some types when it was written with it.
const SHOW_TYPE: u64 = 0x1;
const SHOW_BASIC: u64 = 0x2;
const SHOW_NAME: u64 = 0x4;
const SHOW_OBJECT: u64 = 0x8;

/// One handle of a user-mode minidump's handle data, with the groups of
/// fields `show` selects (`!handle`'s flags).
fn print_user_handle(entry: &UserHandle, show: u64) {
    outln!("handle {:#x}", entry.handle);
    if show & SHOW_TYPE != 0 {
        outln!("  type           {}", handle_type_label(entry));
    }
    if show & SHOW_BASIC != 0 {
        outln!("  access         {:#x}", entry.granted_access);
        let names = handle_attribute_names(entry.attributes);
        if names.is_empty() {
            outln!("  attributes     {:#x}", entry.attributes);
        } else {
            outln!(
                "  attributes     {:#x} ({})",
                entry.attributes,
                names.join(" | ")
            );
        }
        outln!("  handle count   {}", entry.handle_count);
        outln!("  pointer count  {}", entry.pointer_count);
    }
    if show & SHOW_NAME != 0 {
        outln!(
            "  name           {}",
            entry.object_name.as_deref().unwrap_or("-")
        );
    }
    if show & SHOW_OBJECT != 0 {
        match &entry.object_info {
            Some(info) => {
                for (label, value) in object_info_fields(info) {
                    outln!("  {label:<14} {value}");
                }
            }
            None => outln!("  object         {}", ui::muted("not recorded")),
        }
    }
}

/// The fields of a handle's object information, labeled as `!handle`
/// shows them.
fn object_info_fields(info: &HandleObjectInfo) -> Vec<(&'static str, String)> {
    let client = |process: u64, thread: u64| format!("{process:x}.{thread:x}");
    match info {
        HandleObjectInfo::Thread(thread) => vec![
            ("thread", client(thread.process_id, thread.thread_id)),
            ("TEB", ui::addr(thread.teb)),
            ("priority", thread.priority.to_string()),
            ("base priority", thread.base_priority.to_string()),
            ("affinity", format!("{:#x}", thread.affinity)),
            ("exit status", ntstatus_text(thread.exit_status)),
        ],
        HandleObjectInfo::Process(process) => vec![
            ("process", format!("{:x}", process.process_id)),
            ("parent", format!("{:x}", process.parent_process_id)),
            ("PEB", ui::addr(process.peb)),
            ("base priority", process.base_priority.to_string()),
            ("affinity", format!("{:#x}", process.affinity)),
            ("exit status", ntstatus_text(process.exit_status)),
        ],
        HandleObjectInfo::Event(event) => vec![
            (
                "event type",
                if event.manual_reset {
                    "manual reset"
                } else {
                    "auto reset"
                }
                .to_string(),
            ),
            (
                "event state",
                if event.signaled { "set" } else { "waiting" }.to_string(),
            ),
        ],
        HandleObjectInfo::Mutant(mutant) => {
            let state = if mutant.current_count > 0 {
                "free"
            } else {
                "owned"
            };
            let mut fields = vec![
                ("mutex", state.to_string()),
                ("count", mutant.current_count.to_string()),
                (
                    "abandoned",
                    if mutant.abandoned { "yes" } else { "no" }.to_string(),
                ),
            ];
            if let (Some(process), Some(thread)) = (mutant.owner_process_id, mutant.owner_thread_id)
                && (process, thread) != (0, 0)
            {
                fields.push(("owner", client(process, thread)));
            }
            fields
        }
        HandleObjectInfo::Semaphore(semaphore) => vec![
            ("count", semaphore.current_count.to_string()),
            ("limit", semaphore.maximum_count.to_string()),
        ],
        HandleObjectInfo::Section(section) => vec![
            ("section base", format!("{:#x}", section.base_address)),
            ("section flags", format!("{:#x}", section.attributes)),
            ("maximum size", format!("{:#x}", section.maximum_size)),
        ],
        HandleObjectInfo::Other(other) => vec![(
            "object",
            format!(
                "information of kind {} ({} bytes), not decoded",
                other.kind, other.size
            ),
        )],
    }
}

/// An NTSTATUS, with its name when it has one.
fn ntstatus_text(status: u32) -> String {
    match ntstatus_name(status) {
        Some(name) => format!("{status:#x} ({name})"),
        None => format!("{status:#x}"),
    }
}

/// `thread`, an owner of a resource, with its TID and process.
fn owner_label(repl: &ReplState<'_>, owner: &ResourceOwner) -> String {
    let thread = repl.ctx.target.thread_info_from_ethread(owner.thread).ok();
    let who = thread.and_then(|thread| {
        let tid = thread.tid?;
        Some(match thread.process_name {
            Some(process) => format!(" TID {tid} {process}"),
            None => format!(" TID {tid}"),
        })
    });
    format!(
        "{}({}){}",
        ui::addr(owner.thread.0),
        owner.count,
        who.unwrap_or_default()
    )
}

/// How `resource` is owned: exclusively, or shared.
fn ownership(resource: &ExecutiveResource) -> &'static str {
    match (&resource.flags, resource_held(resource)) {
        (_, false) => "-",
        (DiagnosticValue::Available(flags), true) if flags & RESOURCE_OWNED_EXCLUSIVE != 0 => {
            "exclusive"
        }
        (DiagnosticValue::Available(_), true) => "shared",
        (DiagnosticValue::Unavailable(_), true) => "?",
    }
}

fn print_resource(repl: &ReplState<'_>, detail: &ExecutiveResource) {
    let mut notes = UnavailableNotes::default();
    let field = |name: &str, value: String| outln!("  {name:<24} : {value}");
    outln!("ERESOURCE {}", ui::addr(detail.address.0));
    field(
        "ActiveCount",
        notes.value("ActiveCount", &detail.active_count),
    );
    field("Flag", notes.hex("Flag", &detail.flags));
    field(
        "ContentionCount",
        notes.value("ContentionCount", &detail.contention_count),
    );
    field(
        "NumberOfSharedWaiters",
        notes.value("NumberOfSharedWaiters", &detail.shared_waiters),
    );
    field(
        "NumberOfExclusiveWaiters",
        notes.value("NumberOfExclusiveWaiters", &detail.exclusive_waiters),
    );
    match &detail.owners {
        DiagnosticValue::Available(owners) if owners.is_empty() => field("Owners", "-".into()),
        DiagnosticValue::Available(owners) => {
            outln!("  Owners ({})", ownership(detail));
            for owner in owners {
                outln!("    {}", owner_label(repl, owner));
            }
        }
        DiagnosticValue::Unavailable(error) => field("Owners", notes.missing("Owners", error)),
    }
    notes.print("  ");
}

/// `!locks`'s list: one row for each resource, its owners as
/// `thread(count)`.
fn print_resource_table(repl: &ReplState<'_>, resources: &[&ExecutiveResource]) {
    let mut notes = UnavailableNotes::default();
    let mut builder = Builder::default();
    builder.push_record([
        "Resource",
        "Owned",
        "Active",
        "Flags",
        "Contention",
        "Shared waiters",
        "Exclusive waiters",
        "Owners",
    ]);
    for resource in resources {
        let at = |name: &str| format!("{} {name}", ui::addr(resource.address.0));
        let owners = match &resource.owners {
            DiagnosticValue::Available(owners) if owners.is_empty() => "-".to_string(),
            DiagnosticValue::Available(owners) => owners
                .iter()
                .map(|owner| owner_label(repl, owner))
                .collect::<Vec<_>>()
                .join(", "),
            DiagnosticValue::Unavailable(error) => notes.missing(&at("owners"), error),
        };
        builder.push_record([
            ui::addr(resource.address.0).to_string(),
            ownership(resource).to_string(),
            notes.value(&at("active"), &resource.active_count),
            notes.hex(&at("flags"), &resource.flags),
            notes.value(&at("contention"), &resource.contention_count),
            notes.value(&at("shared waiters"), &resource.shared_waiters),
            notes.value(&at("exclusive waiters"), &resource.exclusive_waiters),
            owners,
        ]);
    }
    print_padded_table(builder);
    notes.print("");
}

/// List a limited number of handles of the selected process, or show one handle.
///
/// Without an argument, the command scans up to 256 handle-table slots. With
/// a handle, it shows the object, type, name, access mask, and attributes, if
/// it can decode them. On a user-mode minidump it lists the handles the
/// dump's handle data records, as Windows reported them when the dump was
/// written, with a count of each type. There, a handle of 0 selects every
/// handle, flags choose what to show (1 type, 2 access, attributes, and
/// counts, 4 name, 8 the object-specific information, such as an event's
/// state or a thread's ID, that a dump written with it records for some
/// types; the default shows all but 8), and a type, such as File, keeps
/// only handles of that type.
#[command(
    names = ["!handle"],
    category = "objects and I/O",
    kind = Query,
    target = Nt,
    forms = [process_handle, process_handles],
)]
fn handle(session: &Session, #[arg(parse = handle_query)] query: HandleQuery) -> Result<Handles> {
    let target = &session.target;
    Ok(match query {
        HandleQuery::Kernel(Some(handle)) => Handles::Entry(process_handle(session, handle)?),
        HandleQuery::Kernel(None) => Handles::Table(process_handles(session, 256)?),
        HandleQuery::User {
            handle,
            show,
            type_filter,
        } => Handles::User(UserHandles {
            handle,
            show,
            type_filter,
            handles: target.user_handles()?.to_vec(),
            process: target
                .user_dump_info()
                .map(|info| info.process_label())
                .unwrap_or_default(),
        }),
    })
}

/// What `!handle` shows: on a kernel target one handle or the table's
/// first slots; on a user-mode minidump, its handle data, as WinDbg takes
/// `!handle [handle [flags [type]]]` in user mode.
enum HandleQuery {
    Kernel(Option<u64>),
    User {
        /// 0 is every handle.
        handle: u64,
        show: u64,
        type_filter: Option<String>,
    },
}

/// Decode a handle in the handle table of this process.
#[command(form_of = handle, python = Process, python_name = "handle")]
fn process_handle(session: &Session, value: u64) -> Result<HandleEntry> {
    session.target.inspect_handle(value)
}

/// List a maximum of `limit` handles in the handle table of this process.
#[command(form_of = handle, python = Process, python_name = "handles")]
fn process_handles(
    session: &Session,
    #[arg(sdk, default = 256)] limit: usize,
) -> Result<HandleTable> {
    session.target.enumerate_handles(limit)
}

/// What `!handle` read.
enum Handles {
    Entry(HandleEntry),
    Table(HandleTable),
    User(UserHandles),
}

/// A user-mode minidump's handle data, and what `!handle` was asked to show
/// of it.
struct UserHandles {
    handle: u64,
    show: u64,
    type_filter: Option<String>,
    handles: Vec<UserHandle>,
    /// The dumped process, as its label.
    process: String,
}

#[grammar(
    usage = "[handle-expression [flags [type]]]",
    complete = [Expression, Expression, None]
)]
fn handle_query(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<HandleQuery, ArgError> {
    if cx.state.ctx.target.kind() != TargetKind::UserDump {
        if cursor.remaining() > 1 {
            return Err(ArgError::Message(
                "!handle: flags and a type apply to a user-mode minidump's handle data".into(),
            ));
        }
        return match cursor.word() {
            Some(text) => Ok(HandleQuery::Kernel(Some(cx.eval(&text)?.0))),
            None => Ok(HandleQuery::Kernel(None)),
        };
    }
    if cursor.remaining() > 3 {
        return Err(ArgError::Missing);
    }
    let handle = match cursor.word() {
        Some(text) => cx.eval(&text)?.0,
        None => 0,
    };
    let show = match cursor.word() {
        Some(text) => cx.eval(&text)?.0,
        None => SHOW_TYPE | SHOW_BASIC | SHOW_NAME,
    };
    if show & !(SHOW_TYPE | SHOW_BASIC | SHOW_NAME | SHOW_OBJECT) != 0 {
        return Err(ArgError::Message(format!(
            "!handle: flags {show:#x}: only 1 (type), 2 (access, attributes, counts), 4 (name), and 8 (object) are defined"
        )));
    }
    Ok(HandleQuery::User {
        handle,
        show,
        type_filter: cursor.word().map(String::from),
    })
}

impl Render for Handles {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Entry(entry) => print_handle_entry(entry),
            Self::Table(table) => print_handle_table(table),
            Self::User(handles) => print_user_handles(handles),
        }
    }
}

fn print_handle_entry(entry: &HandleEntry) {
    outln!(
        "handle {:#x}  entry {}",
        entry.handle,
        ui::addr(entry.entry.0)
    );
    let mut notes = UnavailableNotes::default();
    let object = notes.pointer("object", &entry.object);
    let type_name = opt_string_value(&mut notes, "type", &entry.type_name);
    let name = opt_string_value(&mut notes, "name", &entry.name);
    let access = notes.hex("access", &entry.granted_access);
    let attributes = notes.hex("attributes", &entry.attributes);
    outln!("  object      {object}");
    outln!("  type        {type_name}");
    outln!("  name        {name}");
    outln!("  access      {access}");
    outln!("  attributes  {attributes}");
    notes.print("  ");
}

/// An optional string field: its text, or `-` when there is none or it
/// could not be read.
fn opt_string_value(
    notes: &mut UnavailableNotes,
    label: &str,
    value: &DiagnosticValue<Option<String>>,
) -> String {
    match value {
        DiagnosticValue::Available(Some(value)) => value.clone(),
        DiagnosticValue::Available(None) => "-".to_string(),
        DiagnosticValue::Unavailable(error) => notes.missing(label, error),
    }
}

fn print_handle_table(table: &HandleTable) {
    outln!(
        "handles of {} (PID {}): table {}, level {}, {} of {} slots scanned, {} skipped{}",
        table.process.name,
        table.process.pid,
        ui::addr(table.table.0),
        table.table_level,
        table.scanned_handles,
        table.advertised_handles,
        table.skipped_entries,
        if table.truncated {
            " (the scan stops there)"
        } else {
            ""
        }
    );
    let mut notes = UnavailableNotes::default();
    let mut builder = Builder::default();
    builder.push_record(["Handle", "Object", "Type", "Access", "Name"]);
    for entry in &table.entries {
        let at = |name: &str| format!("handle {:#x} {name}", entry.handle);
        builder.push_record([
            format!("{:#x}", entry.handle),
            notes.pointer(&at("object"), &entry.object),
            opt_string_value(&mut notes, &at("type"), &entry.type_name),
            notes.hex(&at("access"), &entry.granted_access),
            opt_string_value(&mut notes, &at("name"), &entry.name),
        ]);
    }
    print_padded_table(builder);
    notes.print("");
}

fn print_user_handles(listing: &UserHandles) {
    let UserHandles {
        handle,
        show,
        type_filter,
        handles,
        process,
    } = listing;
    let (handle, show, type_filter) = (*handle, *show, type_filter.as_deref());
    let shown: Vec<&UserHandle> = handles
        .iter()
        .filter(|entry| handle == 0 || entry.handle == handle)
        .filter(|entry| {
            type_filter.is_none_or(|filter| handle_type_label(entry).eq_ignore_ascii_case(filter))
        })
        .collect();
    if handle != 0 {
        let Some(entry) = shown.first() else {
            match type_filter {
                Some(filter) => error!(
                    "handle {handle:#x} of type {filter} is not in the minidump's handle data"
                ),
                None => error!("handle {handle:#x} is not in the minidump's handle data"),
            }
            return;
        };
        print_user_handle(entry, show);
        return;
    }

    outln!(
        "handles of {process}: {} of {} recorded in the minidump{}",
        shown.len(),
        handles.len(),
        type_filter
            .map(|filter| format!(" (type {filter})"))
            .unwrap_or_default()
    );
    if shown.is_empty() {
        return;
    }
    let mut header = vec!["Handle"];
    if show & SHOW_TYPE != 0 {
        header.push("Type");
    }
    if show & SHOW_BASIC != 0 {
        header.extend(["Access", "Attributes", "Handles", "Pointers"]);
    }
    if show & SHOW_NAME != 0 {
        header.push("Name");
    }
    if show & SHOW_OBJECT != 0 {
        header.push("Object");
    }
    let mut builder = Builder::default();
    builder.push_record(header);
    for entry in &shown {
        let mut row = vec![format!("{:#x}", entry.handle)];
        if show & SHOW_TYPE != 0 {
            row.push(handle_type_label(entry).to_string());
        }
        if show & SHOW_BASIC != 0 {
            row.extend([
                format!("{:#x}", entry.granted_access),
                format!("{:#x}", entry.attributes),
                entry.handle_count.to_string(),
                entry.pointer_count.to_string(),
            ]);
        }
        if show & SHOW_NAME != 0 {
            row.push(entry.object_name.clone().unwrap_or_else(|| "-".to_string()));
        }
        if show & SHOW_OBJECT != 0 {
            row.push(match &entry.object_info {
                Some(info) => object_info_fields(info)
                    .into_iter()
                    .map(|(label, value)| format!("{label} {value}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                None => "-".to_string(),
            });
        }
        builder.push_record(row);
    }
    print_padded_table(builder);

    let mut summary = Builder::default();
    summary.push_record(["Type", "Handles"]);
    for (type_name, count) in handle_type_counts(shown.iter().copied()) {
        summary.push_record([type_name, count.to_string()]);
    }
    // The table above ends with the blank line that sets this one apart.
    outln!("{}", ui::label("by type"));
    print_padded_table(summary);
}

/// Decode a FILE_OBJECT and its relations to its device and name.
#[command(
    names = ["!fileobj"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "file_object",
)]
fn fileobj(session: &Session, address: VirtAddr) -> Result<FileObject> {
    session.target.inspect_file_object(address)
}

impl Render for FileObject {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let file = self;
        outln!("FILE_OBJECT {}", ui::addr(file.address.0));
        let mut notes = UnavailableNotes::default();
        // The device's type and name are not FILE_OBJECT fields: they follow
        // its DeviceObject.
        let device = match &file.device_object {
            DiagnosticValue::Available(device) if !device.is_zero() => {
                let name = opt_string_value(&mut notes, "device name", &file.device_name);
                let kind = notes.hex("device type", &file.device_type);
                format!("{}  {name}  type {kind}", ui::addr(device.0))
            }
            device => notes.pointer("DeviceObject", device),
        };
        let file_name = match &file.file_name {
            DiagnosticValue::Available(name) if name.is_empty() => "-".to_string(),
            name => notes.value("FileName", name),
        };
        let status = match &file.final_status {
            DiagnosticValue::Available(status) => format!("{status:#010x}"),
            DiagnosticValue::Unavailable(error) => notes.missing("FinalStatus", error),
        };
        let offset = match &file.current_byte_offset {
            DiagnosticValue::Available(offset) => format!("{offset:#x}"),
            DiagnosticValue::Unavailable(error) => notes.missing("CurrentByteOffset", error),
        };
        let small =
            |notes: &mut UnavailableNotes, label: &str, value: &DiagnosticValue<i16>| match value {
                DiagnosticValue::Available(value) => format!("{value:#x}"),
                DiagnosticValue::Unavailable(error) => notes.missing(label, error),
            };
        let fields = [
            ("Type", small(&mut notes, "Type", &file.file_type)),
            ("Size", small(&mut notes, "Size", &file.size)),
            ("DeviceObject", device),
            ("FileName", file_name),
            (
                "RelatedFileObject",
                notes.pointer("RelatedFileObject", &file.related_file_object),
            ),
            ("Flags", notes.hex("Flags", &file.flags)),
            ("CurrentByteOffset", offset),
            ("FsContext", notes.pointer("FsContext", &file.fs_context)),
            ("FsContext2", notes.pointer("FsContext2", &file.fs_context2)),
            (
                "SectionObjectPointer",
                notes.pointer("SectionObjectPointer", &file.section_object_pointer),
            ),
            (
                "PrivateCacheMap",
                notes.pointer("PrivateCacheMap", &file.private_cache_map),
            ),
            ("FinalStatus", status),
            (
                "LockOperation",
                notes.yes_no("LockOperation", &file.lock_operation),
            ),
            (
                "DeletePending",
                notes.yes_no("DeletePending", &file.delete_pending),
            ),
            ("ReadAccess", notes.yes_no("ReadAccess", &file.read_access)),
            (
                "WriteAccess",
                notes.yes_no("WriteAccess", &file.write_access),
            ),
            (
                "DeleteAccess",
                notes.yes_no("DeleteAccess", &file.delete_access),
            ),
            ("SharedRead", notes.yes_no("SharedRead", &file.shared_read)),
            (
                "SharedWrite",
                notes.yes_no("SharedWrite", &file.shared_write),
            ),
            (
                "SharedDelete",
                notes.yes_no("SharedDelete", &file.shared_delete),
            ),
        ];
        for (label, value) in fields {
            outln!("  {label:<20} : {value}");
        }
        notes.print("  ");
    }
}

/// Show one ERESOURCE, or the resources of the system resource list that are held.
///
/// Without an argument, the command walks ExpSystemResourcesList, without
/// scanning memory, and shows the resources a thread owns, as WinDbg's does,
/// each owner with its TID and process; -v shows every resource. If the
/// symbol or the list metadata is not available, it cannot list the
/// resources.
#[command(
    names = ["!locks"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [resource, resources],
)]
fn locks(
    session: &Session,
    #[arg(switch = "-v")] all: bool,
    #[arg(name = "resource")] address: Option<VirtAddr>,
) -> Result<Locks> {
    match address {
        Some(address) => resource(session, address).map(Locks::One),
        None => resources(session, MAX_RESOURCES)
            .map(|list| Locks::List { list, all })
            .map_err(|error| {
                Error::DebugInfo(format!("global resource enumeration unavailable: {error}"))
            }),
    }
}

/// Decode an executive resource (`!locks address`).
#[command(form_of = locks, python = Inspect)]
fn resource(session: &Session, address: VirtAddr) -> Result<ExecutiveResource> {
    session.target.inspect_resource(address)
}

/// List the entries of the symbol-backed executive-resource list
/// (`!locks`), at most `limit` of them.
#[command(form_of = locks, python = Inspect)]
fn resources(session: &Session, #[arg(sdk, default = 256)] limit: usize) -> Result<ResourceList> {
    session.target.enumerate_resources(limit)
}

/// What `!locks` read: one resource, or the list, to show whole (`-v`) or
/// only the resources that are held.
enum Locks {
    One(ExecutiveResource),
    List { list: ResourceList, all: bool },
}

/// Whether a thread owns `resource`.
fn resource_held(resource: &ExecutiveResource) -> bool {
    !matches!(resource.active_count, DiagnosticValue::Available(0))
}

impl Render for Locks {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        match self {
            Self::One(resource) => print_resource(repl, resource),
            Self::List { list, all } => {
                let count = list.resources.len();
                let plural = if count == 1 { "" } else { "s" };
                let walk = match &list.termination {
                    ListTermination::Head => format!("{count} resource{plural}"),
                    ListTermination::Null => {
                        format!("{count} resource{plural}, then a null link (the list is corrupt)")
                    }
                    ListTermination::Cycle(address) => format!(
                        "{count} resource{plural}, then a cycle at {:#x} (the list is corrupt)",
                        address.0
                    ),
                    ListTermination::Bound => {
                        format!("the first {count} resource{plural} (the walk stops there)")
                    }
                    ListTermination::Corrupt(error) => {
                        format!("{count} resource{plural}, then a read error: {error}")
                    }
                };
                let shown: Vec<&ExecutiveResource> = list
                    .resources
                    .iter()
                    .filter(|resource| *all || resource_held(resource))
                    .collect();
                let held = list.resources.iter().filter(|r| resource_held(r)).count();
                outln!(
                    "executive resources: list head {}, {walk}, {held} held",
                    ui::addr(list.head.0)
                );
                if shown.is_empty() {
                    outln!(
                        "{}",
                        ui::muted("no resource is held; -v lists every resource")
                    );
                    return;
                }
                print_resource_table(repl, &shown);
            }
        }
    }
}

/// Show the primary token of the selected or current process.
///
/// The command shows the token IDs, user and groups, privileges, type,
/// impersonation level, and flags. It gets each field independently, and if
/// the metadata or memory for a field is missing, it shows this in that field.
#[command(
    names = ["!token"],
    category = "security",
    kind = Query,
    target = Kernel,
    python = Process,
)]
fn token(session: &Session, #[arg(render, parse = no_words)] none: ()) -> Result<Token> {
    session.target.inspect_process_token()
}

/// No argument: any word prints the help, as `!token` always did.
#[grammar(usage = "")]
fn no_words(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<(), ArgError> {
    match cursor.remaining() {
        0 => Ok(()),
        _ => Err(ArgError::Missing),
    }
}

impl Render for Token {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        outln!(
            "TOKEN {}  process {} (PID {})",
            ui::addr(self.token.0),
            self.process.name,
            self.process.pid
        );
        let mut notes = UnavailableNotes::default();
        let field = |name: &str, value: String| outln!("  {name:<18} : {value}");
        field("TokenId", notes.hex("TokenId", &self.token_id));
        field(
            "AuthenticationId",
            notes.hex("AuthenticationId", &self.authentication_id),
        );
        field(
            "TokenType",
            enum_value(&mut notes, "TokenType", &self.token_type, token_type_name),
        );
        field(
            "ImpersonationLevel",
            enum_value(
                &mut notes,
                "ImpersonationLevel",
                &self.impersonation_level,
                impersonation_level_name,
            ),
        );
        field("TokenFlags", notes.hex("TokenFlags", &self.flags));
        let user = match &self.user {
            DiagnosticValue::Available(Some(user)) => format!(
                "{}  {}",
                user.sid,
                flags_text(user.attributes, GROUP_ATTRIBUTES)
            ),
            DiagnosticValue::Available(None) => "-".to_string(),
            DiagnosticValue::Unavailable(error) => notes.missing("User", error),
        };
        field("User", user);
        match &self.groups {
            DiagnosticValue::Available(groups) => {
                outln!("  Groups ({})", groups.len());
                for group in groups {
                    outln!(
                        "    {:<14}  {}",
                        group.sid,
                        flags_text(group.attributes, GROUP_ATTRIBUTES)
                    );
                }
            }
            DiagnosticValue::Unavailable(error) => field("Groups", notes.missing("Groups", error)),
        }
        match &self.privileges {
            DiagnosticValue::Available(privileges) => {
                outln!("  Privileges ({})", privileges.len());
                for privilege in privileges {
                    outln!(
                        "    {:<4}  {:<41}  {}",
                        format!("{:#x}", privilege.luid),
                        privilege_name(privilege.luid).unwrap_or("-"),
                        flags_text(privilege.attributes, PRIVILEGE_ATTRIBUTES)
                    );
                }
            }
            DiagnosticValue::Unavailable(error) => {
                field("Privileges", notes.missing("Privileges", error))
            }
        }
        notes.print("  ");
    }
}

/// An enum value as `Name (0xN)`, or `0xN` for a value with no name.
fn enum_value(
    notes: &mut UnavailableNotes,
    label: &str,
    value: &DiagnosticValue<u32>,
    name: fn(u32) -> Option<&'static str>,
) -> String {
    match value {
        DiagnosticValue::Available(value) => match name(*value) {
            Some(name) => format!("{name} ({value:#x})"),
            None => format!("{value:#x}"),
        },
        DiagnosticValue::Unavailable(error) => notes.missing(label, error),
    }
}

/// A flag set as `0x7 (A | B | C)`; the value alone when no names apply.
fn flags_text(value: u32, names: &[(u32, &str)]) -> String {
    let set: Vec<&str> = names
        .iter()
        .filter(|(bit, _)| value & bit == *bit && *bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if set.is_empty() {
        format!("{value:#x}")
    } else {
        format!("{value:#x} ({})", set.join(" | "))
    }
}

/// `TOKEN_TYPE`.
fn token_type_name(value: u32) -> Option<&'static str> {
    match value {
        1 => Some("TokenPrimary"),
        2 => Some("TokenImpersonation"),
        _ => None,
    }
}

/// `SECURITY_IMPERSONATION_LEVEL`.
fn impersonation_level_name(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("SecurityAnonymous"),
        1 => Some("SecurityIdentification"),
        2 => Some("SecurityImpersonation"),
        3 => Some("SecurityDelegation"),
        _ => None,
    }
}

/// The `SE_GROUP_*` attributes of a token's user and groups.
const GROUP_ATTRIBUTES: &[(u32, &str)] = &[
    (0x1, "SE_GROUP_MANDATORY"),
    (0x2, "SE_GROUP_ENABLED_BY_DEFAULT"),
    (0x4, "SE_GROUP_ENABLED"),
    (0x8, "SE_GROUP_OWNER"),
    (0x10, "SE_GROUP_USE_FOR_DENY_ONLY"),
    (0x20, "SE_GROUP_INTEGRITY"),
    (0x40, "SE_GROUP_INTEGRITY_ENABLED"),
    (0x2000_0000, "SE_GROUP_RESOURCE"),
    (0xc000_0000, "SE_GROUP_LOGON_ID"),
];

/// The `SE_PRIVILEGE_*` attributes of a token's privileges.
const PRIVILEGE_ATTRIBUTES: &[(u32, &str)] = &[
    (0x1, "SE_PRIVILEGE_ENABLED_BY_DEFAULT"),
    (0x2, "SE_PRIVILEGE_ENABLED"),
    (0x4, "SE_PRIVILEGE_REMOVED"),
    (0x8000_0000, "SE_PRIVILEGE_USED_FOR_ACCESS"),
];

/// The name of a well-known privilege LUID (`SE_*_PRIVILEGE` in ntseapi.h).
fn privilege_name(luid: u64) -> Option<&'static str> {
    const NAMES: [&str; 35] = [
        "SeCreateTokenPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeLockMemoryPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeMachineAccountPrivilege",
        "SeTcbPrivilege",
        "SeSecurityPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeSystemProfilePrivilege",
        "SeSystemtimePrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeIncreaseBasePriorityPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeDebugPrivilege",
        "SeAuditPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeChangeNotifyPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeUndockPrivilege",
        "SeSyncAgentPrivilege",
        "SeEnableDelegationPrivilege",
        "SeManageVolumePrivilege",
        "SeImpersonatePrivilege",
        "SeCreateGlobalPrivilege",
        "SeTrustedCredManAccessPrivilege",
        "SeRelabelPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeTimeZonePrivilege",
        "SeCreateSymbolicLinkPrivilege",
        "SeDelegateSessionUserImpersonatePrivilege",
    ];
    // The well-known privileges are LUIDs 2 through 36, in this order.
    luid.checked_sub(2)
        .and_then(|index| NAMES.get(usize::try_from(index).ok()?))
        .copied()
}
