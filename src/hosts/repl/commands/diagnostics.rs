use std::fmt::Display;

use tabled::builder::Builder;

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::mm::SystemMemorySummary;
use crate::nt::target::object::{
    ExecutiveResource, FileObject, HandleEntry, HandleTable, ResourceList,
};
use crate::nt::target::security::Token;
use crate::nt::target::usermode::handles::{
    handle_attribute_names, handle_type_counts, handle_type_label,
};
use crate::nt::target::{DiagnosticMetric, DiagnosticValue, ListTermination, TargetKind};
use crate::nt::userdump::UserHandle;
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
        print_memory_use_summary(self, true);
    }
}

pub fn diagnostic_cell<T: Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

pub fn diagnostic_metric_cell<T: Display>(metric: &DiagnosticMetric<T>) -> String {
    match metric.source {
        Some(source) => format!("{} [{source}]", diagnostic_cell(&metric.value)),
        None => diagnostic_cell(&metric.value),
    }
}

pub fn print_memory_use_summary(summary: &SystemMemorySummary, include_process_stats: bool) {
    outln!("system memory (page counters are pages; nonpaged pool is bytes)");
    outln!(
        "  physical pages     : {}",
        diagnostic_metric_cell(&summary.physical_pages)
    );
    outln!(
        "  available pages    : {}",
        diagnostic_metric_cell(&summary.available_pages)
    );
    outln!(
        "  committed pages    : {}",
        diagnostic_metric_cell(&summary.committed_pages)
    );
    outln!(
        "  commit limit pages : {}",
        diagnostic_metric_cell(&summary.commit_limit_pages)
    );
    outln!(
        "  paged pool pages   : {}",
        diagnostic_metric_cell(&summary.paged_pool_pages)
    );
    outln!(
        "  nonpaged pool bytes: {}",
        diagnostic_metric_cell(&summary.nonpaged_pool_bytes)
    );
    if include_process_stats && !summary.processes.is_empty() {
        let mut builder = Builder::default();
        builder.push_record([
            "PID",
            "Process",
            "Virtual",
            "Working set",
            "Pagefile",
            "Private",
        ]);
        for process in &summary.processes {
            builder.push_record([
                process.process.pid.to_string(),
                process.process.name.clone(),
                diagnostic_cell(&process.virtual_size),
                diagnostic_cell(&process.working_set_size),
                diagnostic_cell(&process.pagefile_usage),
                diagnostic_cell(&process.private_usage),
            ]);
        }
        print_padded_table(builder);
    }
    if include_process_stats && summary.truncated {
        outln!(
            "process list bounded: displayed {} of {}",
            summary.processes.len(),
            summary.process_count
        );
    }
}

pub fn diagnostic_hex<T>(value: &DiagnosticValue<T>) -> String
where
    T: Copy + Into<u64>,
{
    match value {
        DiagnosticValue::Available(value) => format!("{:#x}", (*value).into()),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_status(value: &DiagnosticValue<u32>) -> String {
    match value {
        DiagnosticValue::Available(value) => format!("{value:#010x}"),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

pub fn diagnostic_addr(value: &DiagnosticValue<VirtAddr>) -> String {
    match value {
        DiagnosticValue::Available(value) => ui::addr(value.0).to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_opt_string(value: &DiagnosticValue<Option<String>>) -> String {
    match value {
        DiagnosticValue::Available(Some(value)) => value.clone(),
        DiagnosticValue::Available(None) => "-".to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

/// `!handle`'s flags on a user-mode minidump, as WinDbg's user-mode flags:
/// the handle's type; its access, attributes, and counts; its object's
/// name; and object-specific information, which a minidump does not record.
const SHOW_TYPE: u64 = 0x1;
const SHOW_BASIC: u64 = 0x2;
const SHOW_NAME: u64 = 0x4;
const SHOW_OBJECT: u64 = 0x8;

/// One handle of a user-mode minidump's handle data, with the groups of
/// fields `show` selects (`!handle`'s flags).
fn print_user_handle(entry: &UserHandle, show: u64) {
    outln!("handle {:#x}", entry.handle);
    if show & SHOW_TYPE != 0 {
        outln!("  type          : {}", handle_type_label(entry));
    }
    if show & SHOW_BASIC != 0 {
        outln!("  access        : {:#x}", entry.granted_access);
        let names = handle_attribute_names(entry.attributes);
        if names.is_empty() {
            outln!("  attributes    : {:#x}", entry.attributes);
        } else {
            outln!(
                "  attributes    : {:#x} ({})",
                entry.attributes,
                names.join(" | ")
            );
        }
        outln!("  handle count  : {}", entry.handle_count);
        outln!("  pointer count : {}", entry.pointer_count);
    }
    if show & SHOW_NAME != 0 {
        outln!(
            "  name          : {}",
            entry.object_name.as_deref().unwrap_or("-")
        );
    }
}

fn print_resource(detail: &ExecutiveResource) {
    outln!("ERESOURCE {}", ui::addr(detail.address.0));
    outln!(
        "  active count       : {}",
        diagnostic_cell(&detail.active_count)
    );
    outln!("  flags              : {}", diagnostic_hex(&detail.flags));
    outln!(
        "  contention count   : {}",
        diagnostic_cell(&detail.contention_count)
    );
    outln!(
        "  shared waiters     : {}",
        diagnostic_cell(&detail.shared_waiters)
    );
    outln!(
        "  exclusive waiters  : {}",
        diagnostic_cell(&detail.exclusive_waiters)
    );
    match &detail.owners {
        DiagnosticValue::Available(owners) if owners.is_empty() => {
            outln!("  owners             : none")
        }
        DiagnosticValue::Available(owners) => {
            outln!("  owners:");
            for owner in owners {
                outln!("    {} count {}", ui::addr(owner.thread.0), owner.count);
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!("  owners             : <unavailable: {error}>")
        }
    }
}

/// List a limited number of handles of the selected process, or show one handle.
///
/// Without an argument, the command scans up to 256 handle-table slots. With
/// a handle, it shows the object, type, name, access mask, and attributes, if
/// it can decode them. On a user-mode minidump it lists the handles the
/// dump's handle data records, as Windows reported them when the dump was
/// written, with a count of each type; it has no objects to show. There, a
/// handle of 0 selects every handle, flags choose what to show (1 type, 2
/// access, attributes, and counts, 4 name; the default shows all), and a
/// type, such as File, keeps only handles of that type.
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
    outln!("  object      : {}", diagnostic_addr(&entry.object));
    outln!(
        "  type        : {}",
        diagnostic_opt_string(&entry.type_name)
    );
    outln!("  name        : {}", diagnostic_opt_string(&entry.name));
    outln!("  access      : {}", diagnostic_hex(&entry.granted_access));
    outln!("  attributes  : {}", diagnostic_hex(&entry.attributes));
}

fn print_handle_table(table: &HandleTable) {
    outln!(
        "handles: {} ({})  table {} level {}  scanned {}/{} slots, {} skipped{}",
        table.process.name,
        table.process.pid,
        ui::addr(table.table.0),
        table.table_level,
        table.scanned_handles,
        table.advertised_handles,
        table.skipped_entries,
        if table.truncated { " (bounded)" } else { "" }
    );
    let mut builder = Builder::default();
    builder.push_record(["Handle", "Object", "Type", "Access", "Name"]);
    for entry in &table.entries {
        builder.push_record([
            format!("{:#x}", entry.handle),
            diagnostic_addr(&entry.object),
            diagnostic_opt_string(&entry.type_name),
            diagnostic_hex(&entry.granted_access),
            diagnostic_opt_string(&entry.name),
        ]);
    }
    print_padded_table(builder);
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
    if show & SHOW_OBJECT != 0 {
        outln!(
            "{}",
            ui::muted("object-specific information is not recorded in a user-mode minidump")
        );
    }
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
        outln!();
        return;
    }

    outln!(
        "handles: {process}, {} of {} the minidump records{}",
        shown.len(),
        handles.len(),
        type_filter
            .map(|filter| format!(" (type {filter})"))
            .unwrap_or_default()
    );
    if shown.is_empty() {
        outln!();
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
        builder.push_record(row);
    }
    print_padded_table(builder);

    let mut summary = Builder::default();
    summary.push_record(["Type", "Handles"]);
    for (type_name, count) in handle_type_counts(shown.iter().copied()) {
        summary.push_record([type_name, count.to_string()]);
    }
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
        outln!(
            "  type / size        : {} / {}",
            diagnostic_cell(&file.file_type),
            diagnostic_cell(&file.size)
        );
        outln!(
            "  device             : {}",
            diagnostic_addr(&file.device_object)
        );
        outln!(
            "  device type        : {}",
            diagnostic_hex(&file.device_type)
        );
        outln!(
            "  device name        : {}",
            diagnostic_opt_string(&file.device_name)
        );
        outln!(
            "  file name          : {}",
            diagnostic_cell(&file.file_name)
        );
        outln!(
            "  related file       : {}",
            diagnostic_addr(&file.related_file_object)
        );
        outln!("  flags              : {}", diagnostic_hex(&file.flags));
        outln!(
            "  current offset     : {}",
            diagnostic_cell(&file.current_byte_offset)
        );
        outln!(
            "  fs context         : {}",
            diagnostic_addr(&file.fs_context)
        );
        outln!(
            "  fs context 2       : {}",
            diagnostic_addr(&file.fs_context2)
        );
        outln!(
            "  section object ptr : {}",
            diagnostic_addr(&file.section_object_pointer)
        );
        outln!(
            "  private cache map  : {}",
            diagnostic_addr(&file.private_cache_map)
        );
        outln!(
            "  final status       : {}",
            diagnostic_status(&file.final_status)
        );
        outln!(
            "  lock operation     : {}",
            diagnostic_cell(&file.lock_operation)
        );
        outln!(
            "  delete pending     : {}",
            diagnostic_cell(&file.delete_pending)
        );
        outln!(
            "  access R/W/D       : {}/{}/{}",
            diagnostic_cell(&file.read_access),
            diagnostic_cell(&file.write_access),
            diagnostic_cell(&file.delete_access)
        );
        outln!(
            "  shared R/W/D       : {}/{}/{}",
            diagnostic_cell(&file.shared_read),
            diagnostic_cell(&file.shared_write),
            diagnostic_cell(&file.shared_delete)
        );
    }
}

/// Show one ERESOURCE, or list the resources in the system resource list.
///
/// Without an argument, the command uses ExpSystemResourcesList and shows up
/// to 256 entries without scanning memory. If the symbol or the list metadata
/// is not available, it cannot list the resources.
#[command(
    names = ["!locks"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [resource, resources],
)]
fn locks(session: &Session, #[arg(name = "resource")] address: Option<VirtAddr>) -> Result<Locks> {
    match address {
        Some(address) => resource(session, address).map(Locks::One),
        None => resources(session, 256).map(Locks::List).map_err(|error| {
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

/// What `!locks` read.
enum Locks {
    One(ExecutiveResource),
    List(ResourceList),
}

impl Render for Locks {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::One(resource) => print_resource(resource),
            Self::List(list) => {
                outln!(
                    "executive resources: head {} entries {} termination {}",
                    ui::addr(list.head.0),
                    list.resources.len(),
                    match &list.termination {
                        ListTermination::Head => "head".to_string(),
                        ListTermination::Null => "null (corrupt)".to_string(),
                        ListTermination::Cycle(address) => {
                            format!("cycle at {} (corrupt)", ui::addr(address.0))
                        }
                        ListTermination::Bound => "bound (truncated)".to_string(),
                        ListTermination::Corrupt(error) => format!("read error: {error}"),
                    }
                );
                list.resources.iter().for_each(print_resource);
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
            "token: {} ({})  {}",
            self.process.name,
            self.process.pid,
            ui::addr(self.token.0)
        );
        outln!("  token id           : {}", diagnostic_hex(&self.token_id));
        outln!(
            "  authentication id  : {}",
            diagnostic_hex(&self.authentication_id)
        );
        outln!(
            "  type               : {}",
            diagnostic_cell(&self.token_type)
        );
        outln!(
            "  impersonation      : {}",
            diagnostic_cell(&self.impersonation_level)
        );
        outln!("  flags              : {}", diagnostic_hex(&self.flags));
        match &self.user {
            DiagnosticValue::Available(Some(user)) => outln!(
                "  user               : {} attributes {:#x}",
                user.sid,
                user.attributes
            ),
            DiagnosticValue::Available(None) => outln!("  user               : none"),
            DiagnosticValue::Unavailable(error) => {
                outln!("  user               : <unavailable: {error}>")
            }
        }
        match &self.groups {
            DiagnosticValue::Available(groups) => {
                outln!("  groups ({})", groups.len());
                for group in groups {
                    outln!("    {} attributes {:#x}", group.sid, group.attributes);
                }
            }
            DiagnosticValue::Unavailable(error) => {
                outln!("  groups             : <unavailable: {error}>")
            }
        }
        match &self.privileges {
            DiagnosticValue::Available(privileges) => {
                outln!("  privileges ({})", privileges.len());
                for privilege in privileges {
                    outln!(
                        "    LUID {:#x} attributes {:#x}",
                        privilege.luid,
                        privilege.attributes
                    );
                }
            }
            DiagnosticValue::Unavailable(error) => {
                outln!("  privileges         : <unavailable: {error}>")
            }
        }
    }
}
