//! Process-state inspectors: job objects, global flags, handle traces, ALPC
//! ports, and exited processes and threads still referenced.

use crate::error::Result;
use crate::guest::ProcessInfo;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::DiagnosticValue;
use crate::target::alpc::{
    AlpcConnection, AlpcMessage, AlpcPort, AlpcPortKind, AlpcProcessPorts, lpc_message_type_name,
};
use crate::target::etw::format_filetime_precise;
use crate::target::gflag::{GLOBAL_FLAGS, GlobalFlagChange, GlobalFlags, global_flags_set};
use crate::target::htrace::HandleTraces;
use crate::target::job::{Job, job_limit_flag_names};
use crate::target::zombies::{MAX_ZOMBIES, ZombieKinds, Zombies};
use crate::types::VirtAddr;
use crate::ui;
use ntoseye_macros::command;

/// Show an ALPC port, an ALPC message, or the ports that a process holds.
///
/// /p decodes an _ALPC_PORT from its object body or header. It shows the
/// kind, owner, and state flags of the port, and the connection, server, and
/// client ports of its communication info. It also shows the queues of the
/// port with the messages on them, and the threads on the wait queue. For a
/// connection port, /p also lists the connections. /m decodes a
/// _KALPC_MESSAGE and shows the IDs, type, sizes, and state of the message,
/// its owner and queue ports, and the waiting and server threads. /lpp walks
/// the handle table of a process to find ALPC ports. The process can be an
/// EPROCESS address, a PID, or a name, and the default is the current
/// process. /lpp first shows the connection ports that the process owns and,
/// for each connection, the server and client ports and the client process.
/// Then it shows the ports that the process is connected to. The number
/// after a port is the count of its queued messages in the main,
/// large-message, and pending queues.
#[command(
    names = ["!alpc", "alpc"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [alpc_port, alpc_message, alpc_process_ports],
    usage = "!alpc /p <port> | /m <message> | /lpp [process]",
    completion = [Expression, Expression]
)]
fn alpc(session: &Session, #[arg(parse = alpc_query)] query: AlpcQuery) -> Result<AlpcObject> {
    Ok(match query {
        AlpcQuery::Port(address) => AlpcObject::Port(alpc_port(session, address)?),
        AlpcQuery::Message(address) => AlpcObject::Message(alpc_message(session, address)?),
        AlpcQuery::ProcessPorts(process) => {
            AlpcObject::ProcessPorts(alpc_process_ports(session, Some(process))?)
        }
    })
}

/// Decode an ALPC port (`!alpc /p`). The result has the port kind, owner,
/// connection, state, and queues, and for a connection port also its
/// connections. `address` is the body or the header of the port object.
#[command(form_of = alpc, python = Inspect, word = "/p")]
fn alpc_port(
    session: &Session,
    #[arg(name = "port", complete = Expression)] address: VirtAddr,
) -> Result<AlpcPort> {
    session.target.alpc_port(address)
}

/// Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
#[command(form_of = alpc, python = Inspect, word = "/m")]
fn alpc_message(
    session: &Session,
    #[arg(name = "message", complete = Expression)] address: VirtAddr,
) -> Result<AlpcMessage> {
    session.target.alpc_message(address)
}

/// Get the ALPC ports to which a process has handles (`!alpc /lpp`). The
/// result has the connection ports that the process owns, with their
/// connections, and the client ports through which the process is
/// connected. `process` defaults to the current process.
#[command(form_of = alpc, python = Inspect, word = "/lpp")]
fn alpc_process_ports(
    session: &Session,
    #[arg(complete = Process, positional)] process: Option<ProcessInfo>,
) -> Result<AlpcProcessPorts> {
    let target = &session.target;
    let process = match process {
        Some(process) => process,
        None => target.selected_process_info()?,
    };
    target.alpc_process_ports(process)
}

/// What `!alpc` decodes: its switch and the argument after it.
enum AlpcQuery {
    Port(VirtAddr),
    Message(VirtAddr),
    ProcessPorts(ProcessInfo),
}

/// What `!alpc` decoded.
enum AlpcObject {
    Port(AlpcPort),
    Message(AlpcMessage),
    ProcessPorts(AlpcProcessPorts),
}

fn alpc_query(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AlpcQuery, ArgError> {
    let usage =
        || ArgError::Message("usage: !alpc /p <port> | /m <message> | /lpp [process]".into());
    let switch = cursor.word().ok_or_else(usage)?.to_ascii_lowercase();
    match switch.as_str() {
        form @ ("/p" | "/m") => {
            let address = cx.eval(&cursor.word().ok_or_else(usage)?)?;
            Ok(if form == "/p" {
                AlpcQuery::Port(address)
            } else {
                AlpcQuery::Message(address)
            })
        }
        "/lpp" => cx
            .state
            .process_or_current(cursor.word().as_deref())
            .map(AlpcQuery::ProcessPorts)
            .map_err(|error| ArgError::Message(error.to_string())),
        _ => Err(usage()),
    }
}

impl Render for AlpcObject {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Port(port) => print_alpc_port(port),
            Self::Message(message) => print_alpc_message(message),
            Self::ProcessPorts(ports) => print_alpc_process_ports(ports),
        }
    }
}

/// Show or change nt!NtGlobalFlag, and show the PEB flags of the current process.
///
/// Without an argument, the command decodes nt!NtGlobalFlag and the
/// _PEB.NtGlobalFlag of the current process and shows the bits by their
/// GFlags names. `+` sets bits and `-` clears bits, from a value or from one
/// flag that you name by its three-letter abbreviation (`!gflag +ust`). A
/// value without `+` or `-` replaces nt!NtGlobalFlag. Each change is one
/// 4-byte write to nt!NtGlobalFlag, the same write that `ed` makes, and the
/// command does not change the PEB copy. `-?` lists the flags and their
/// abbreviations.
#[command(
    names = ["!gflag", "gflag"],
    category = "analysis",
    kind = Action,
    target = Kernel,
    forms = [global_flags, set_global_flags],
    usage = "!gflag [[+|-]value | {+|-}abbreviation | -?]",
    completion = [Expression]
)]
fn gflag(
    session: &Session,
    #[arg(render, switch = "-?")] list: bool,
    change: Option<GlobalFlagChange>,
) -> Result<GlobalFlags> {
    match change {
        Some(change) => set_global_flags(session, change),
        None => global_flags(session),
    }
}

/// Decode nt!NtGlobalFlag and the _PEB.NtGlobalFlag of the current process
/// (`!gflag`): the value of each and the bits by their GFlags names.
#[command(form_of = gflag, python = Inspect)]
fn global_flags(session: &Session) -> Result<GlobalFlags> {
    session.target.global_flags()
}

/// Change nt!NtGlobalFlag and decode the flags as they now are (`!gflag
/// +ust`). `change` is `+` or `-` and a value or a flag's three-letter
/// abbreviation, which sets or clears those bits, or a value without a sign,
/// which replaces nt!NtGlobalFlag. It is one 4-byte write to
/// nt!NtGlobalFlag; the PEB copy does not change. The result's `change`
/// has the value before and after.
#[command(form_of = gflag, python = Inspect)]
fn set_global_flags(session: &Session, change: GlobalFlagChange) -> Result<GlobalFlags> {
    let target = &session.target;
    let change = target.change_global_flag(change)?;
    Ok(GlobalFlags {
        change: Some(change),
        ..target.global_flags()?
    })
}

/// Show the stacks that handle tracing recorded for the handles of a process.
///
/// Reads the ring of traces (open, close, bad reference) in the DebugInfo of
/// the process handle table and shows the newest trace first. If handle is 0
/// or not given, the command shows the traces of all handles, and if
/// max-traces is 0 or not given, it shows all traces. The process can be an
/// EPROCESS address, a PID, or a name, and the default is the current
/// process. Handle tracing must be on for the process before you use the
/// command. The Handles check of Application Verifier or
/// NtSetInformationProcess(ProcessHandleTracing) turns tracing on, and if it
/// is off, !htrace shows a message. User-mode frames resolve after the
/// modules of the process are loaded (.process /p). The command does not
/// have the user-mode forms that change tracing (-enable, -disable,
/// -snapshot, -diff).
#[command(
    names = ["!htrace", "htrace"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Process,
    python_name = "handle_traces",
    usage = "!htrace [handle [process [max-traces]]]",
    completion = [Expression, Expression, Expression]
)]
fn htrace(
    session: &Session,
    #[arg(positional)] handle: Option<u64>,
    #[arg(receiver, parse = process_or_current)] process: ProcessInfo,
    max_traces: Option<u64>,
) -> Result<HandleTraces> {
    // A handle or max-traces of 0, like an omitted one, means all.
    let nonzero = |value: Option<u64>| value.filter(|&value| value != 0);
    session.target.handle_traces(
        &process,
        nonzero(handle),
        nonzero(max_traces).map(|max| max as usize),
    )
}

/// A process argument: an EPROCESS, a PID, or an image name; omitted or 0,
/// the current process.
fn process_or_current(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ProcessInfo, ArgError> {
    let selector = cursor.word().filter(|text| text != "0");
    cx.state
        .process_or_current(selector.as_deref())
        .map_err(|error| ArgError::Message(error.to_string()))
}

impl Render for HandleTraces {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_handle_traces(self);
    }
}

/// List exited processes and threads that still have references.
///
/// Scans nonpaged pool for process (`Proc`) and thread (`Thre`) objects, and
/// finds the header of each object by its decoded type. The command lists
/// the processes that have ExitTime set and the threads in the Terminated
/// state. For each object, it shows the handle count and the pointer count:
/// whatever still holds these references keeps the object in memory. Flag 1
/// (the default) lists processes, 2 lists threads, and 3 lists both. The
/// scan stops after 4096 processes or 4096 threads, or when you press
/// Ctrl+C.
#[command(
    names = ["!zombies", "zombies"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn zombies(session: &Session, #[arg(default = 1)] flags: u64) -> Result<Zombies> {
    session.target.zombies(ZombieKinds::from_flags(flags)?)
}

impl Render for Zombies {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_zombies(self);
    }
}

impl Render<bool> for GlobalFlags {
    fn render(&self, _: &mut ReplState<'_>, list: bool) {
        if list {
            for flag in &GLOBAL_FLAGS {
                outln!(
                    "  {:#010x} {:<3} {}",
                    flag.bit,
                    flag.abbreviation,
                    flag.description
                );
            }
            outln!();
            return;
        }
        if let Some(change) = &self.change {
            outln!("NtGlobalFlag {:#010x} -> {:#010x}", change.old, change.new);
        }
        print_global_flags(self);
    }
}

/// Show a job object and the processes in it.
///
/// Shows a job object. The address can be a job, or a process or thread, for
/// which the command shows its job. If you do not give an address, or give 0,
/// the command shows the job of the current process. Flag 1 (the default)
/// shows the accounting, limits, and flags of the job, and also the child
/// jobs, the parent and root job, and the silo state. Flag 2 lists the
/// processes assigned to the job (from ProcessListHead).
#[command(
    names = ["!job", "job"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!job [address [flags]]"
)]
fn job(
    session: &mut Session,
    #[arg(positional)] address: Option<VirtAddr>,
    #[arg(render, default = 1)] flags: u64,
) -> Result<Job> {
    let target = &session.target;
    target.inspect_job(target.job_address(address)?)
}

impl Render<u64> for Job {
    fn render(&self, _: &mut ReplState<'_>, flags: u64) {
        print_job(self, flags);
    }
}

fn print_job(job: &Job, flags: u64) {
    outln!("Job at {}", ui::addr(job.address.0));
    let optional = |value: Option<u64>| value.map_or("-".to_string(), |value| value.to_string());
    outln!(
        "  JobId {}  SessionId {}",
        optional(job.job_id),
        optional(job.session_id)
    );
    if flags & 1 != 0 {
        outln!("  Basic Accounting Information");
        for (field, value) in job.accounting.fields() {
            if let Some(value) = value {
                outln!("    {:<28} {value:#x}", format!("{field}:"));
            }
        }
        outln!("  Job Flags ({})", optional_hex(job.job_flags));
        for name in &job.job_flag_names {
            outln!("    [{name}]");
        }
        outln!("  Limit Information");
        for (field, value) in job.limits.fields() {
            let Some(value) = value else { continue };
            let names = if field.ends_with("LimitFlags") {
                format!(" {}", job_limit_flag_names(value).join(" "))
            } else {
                String::new()
            };
            outln!("    {:<28} {value:#x}{names}", format!("{field}:"));
        }
        outln!(
            "  Nesting: depth {}  parent {}  root {}",
            optional(job.nesting_depth),
            optional_addr(job.parent_job),
            optional_addr(job.root_job)
        );
        for child in &job.child_jobs {
            outln!("    child job {}", ui::addr(child.0));
        }
        if let Some(why) = job.child_job_list_termination.diagnostic() {
            outln!("    child job list ended early: {why}");
        }
        if job.silo {
            outln!(
                "  Silo: ServerSiloGlobals {}",
                optional_addr(job.server_silo_globals)
            );
        }
    }
    if flags & 2 != 0 {
        outln!("  Processes assigned to this job:");
        for process in &job.processes {
            outln!(
                "    PROCESS {}  Cid: {:04x}  Image: {}",
                ui::addr(process.eprocess.0),
                process.pid,
                process.name
            );
        }
        for eprocess in &job.unreadable_processes {
            outln!("    PROCESS {}  (unreadable)", ui::addr(eprocess.0));
        }
        if let Some(why) = job.process_list_termination.diagnostic() {
            outln!("    process list ended early: {why}");
        }
    }
    outln!();
}

fn print_global_flags(detail: &GlobalFlags) {
    let print_flags = |value: u32| {
        for flag in global_flags_set(value) {
            let abbreviation = if flag.abbreviation.is_empty() {
                format!("{:#x}", flag.bit)
            } else {
                flag.abbreviation.to_string()
            };
            outln!("    {abbreviation} - {}", flag.description);
        }
    };
    outln!(
        "NtGlobalFlag at {}: {:#010x}",
        ui::addr(detail.kernel_address.0),
        detail.kernel
    );
    print_flags(detail.kernel);
    if let Some(process) = &detail.process {
        match &detail.process_flags {
            DiagnosticValue::Available(flags) => {
                outln!(
                    "PEB NtGlobalFlag of {} (PID {}): {flags:#010x}",
                    process.name,
                    process.pid
                );
                print_flags(*flags);
            }
            DiagnosticValue::Unavailable(error) => outln!(
                "PEB NtGlobalFlag of {} (PID {}): unavailable ({error})",
                process.name,
                process.pid
            ),
        }
    }
    outln!();
}

fn print_handle_traces(detail: &HandleTraces) {
    let process = &detail.process;
    outln!(
        "Process {} ({}, PID {})",
        ui::addr(process.eprocess.0),
        process.name,
        process.pid
    );
    outln!("ObjectTable {}", ui::addr(detail.object_table.0));
    let Some(debug_info) = detail.debug_info else {
        outln!("Handle tracing is not enabled for this process.\n");
        return;
    };
    outln!(
        "DebugInfo {}  TableSize {:#x}  {:#x} trace(s) recorded",
        ui::addr(debug_info.0),
        detail.table_size,
        detail.recorded
    );
    let separator = "-".repeat(38);
    outln!("{separator}");
    for trace in &detail.traces {
        outln!("Handle {:#x} - {}:", trace.handle, trace.kind_name());
        outln!(
            "Thread ID = {:#x}, Process ID = {:#x}",
            trace.thread_id,
            trace.process_id
        );
        for frame in &trace.stack {
            match &frame.symbol {
                Some(symbol) => outln!("{}: {}", ui::addr(frame.address.0), ui::symbol(symbol)),
                None => outln!("{}", ui::addr(frame.address.0)),
            }
        }
        outln!("{separator}");
    }
    outln!("Parsed {:#x} stack trace(s).", detail.parsed);
    outln!("Dumped {:#x} stack trace(s).", detail.traces.len());
    if detail.unreadable != 0 {
        outln!("{:#x} trace slot(s) unreadable.", detail.unreadable);
    }
    outln!();
}

fn optional_addr(value: Option<VirtAddr>) -> String {
    value.map_or("-".to_string(), |value| ui::addr(value.0))
}

fn optional_hex(value: Option<u64>) -> String {
    value.map_or("-".to_string(), |value| format!("{value:#x}"))
}

/// `[a] [b] ...`.
fn bracketed(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("[{name}]"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or("?".to_string(), |value| value.to_string())
}

fn owner_label(owner: VirtAddr, name: &Option<String>) -> String {
    format!("{} ({})", ui::addr(owner.0), name.as_deref().unwrap_or("?"))
}

fn kind_name(kind: Option<AlpcPortKind>) -> &'static str {
    kind.map_or("unknown", |kind| kind.as_str())
}

fn print_alpc_connection(connection: &AlpcConnection) {
    outln!(
        "    {} {} -> {} {} {}",
        ui::addr(connection.server_port.0),
        optional_count(connection.server_queued),
        ui::addr(connection.client_port.0),
        optional_count(connection.client_queued),
        owner_label(connection.client_owner, &connection.client_owner_name)
    );
}

fn print_alpc_port(port: &AlpcPort) {
    match &port.name {
        Some(name) => outln!("Port {} ('{name}')", ui::addr(port.address.0)),
        None => outln!("Port {}", ui::addr(port.address.0)),
    }
    let row = |label: &str, value: String| outln!("  {label:<24}: {value}");
    row(
        "Type",
        format!(
            "{} (Type bits {})",
            kind_name(port.kind),
            optional_hex(port.port_type)
        ),
    );
    row(
        "PointerCount/Handles",
        format!("{} / {}", port.pointer_count, port.handle_count),
    );
    row("OwnerProcess", owner_label(port.owner, &port.owner_name));
    row("CommunicationInfo", ui::addr(port.communication_info.0));
    row("  ConnectionPort", optional_addr(port.connection_port));
    row("  ServerCommunicationPort", optional_addr(port.server_port));
    row("  ClientCommunicationPort", optional_addr(port.client_port));
    row("SequenceNo", optional_hex(port.sequence_no));
    row("CompletionPort", optional_addr(port.completion_port));
    row("CompletionList", optional_addr(port.completion_list));
    row("PortContext", optional_addr(port.port_context));
    row("PortAttributes.Flags", optional_hex(port.attribute_flags));
    row("MaxMessageLength", optional_hex(port.max_message_length));
    row(
        "State",
        format!(
            "{} {}",
            optional_hex(port.state),
            bracketed(&port.state_flags)
        ),
    );
    outln!();
    for queue in &port.queues {
        let what = if queue.key == "wait" {
            "thread(s)"
        } else {
            "message(s)"
        };
        outln!(
            "  {}: {} {what} (length {})",
            queue.field,
            queue.entries.len(),
            optional_count(queue.length)
        );
        for entry in &queue.entries {
            outln!("    {}", ui::addr(entry.0));
        }
        if let Some(why) = queue.termination.diagnostic() {
            outln!("    walk ended early: {why}");
        }
    }
    outln!(
        "  DirectQueue: length {}",
        optional_count(port.direct_queue_length)
    );
    if let Some(termination) = &port.connection_termination {
        outln!();
        outln!(
            "  {} connection(s) (server port, queued -> client port, queued, client process):",
            port.connections.len()
        );
        port.connections.iter().for_each(print_alpc_connection);
        if let Some(why) = termination.diagnostic() {
            outln!("    connection list ended early: {why}");
        }
    }
    outln!();
}

fn print_alpc_message(message: &AlpcMessage) {
    outln!("Message {}", ui::addr(message.address.0));
    let row = |label: &str, value: String| outln!("  {label:<22}: {value}");
    let number =
        |value: Option<u64>| value.map_or("-".to_string(), |value| format!("{value:#x} ({value})"));
    row("MessageID", number(message.message_id));
    row("CallbackID", number(message.callback_id));
    row("SequenceNumber", number(message.sequence_no));
    row(
        "Type",
        match message.message_type {
            Some(value) => format!(
                "{} ({value:#x})",
                lpc_message_type_name(value).unwrap_or("unknown")
            ),
            None => "-".to_string(),
        },
    );
    row("DataLength", number(message.data_length));
    row("TotalLength", number(message.total_length));
    row(
        "ClientId",
        format!(
            "{}.{}",
            optional_hex(message.client_process_id),
            optional_hex(message.client_thread_id)
        ),
    );
    row(
        "State",
        format!(
            "{} QueueType {} QueuePortType {} {}",
            optional_hex(message.state),
            optional_count(message.queue_type),
            optional_count(message.queue_port_type),
            bracketed(&message.state_flags)
        ),
    );
    row(
        "OwnerPort",
        format!(
            "{} [{}]",
            ui::addr(message.owner_port.0),
            kind_name(message.owner_port_kind)
        ),
    );
    row(
        "QueuePort",
        format!(
            "{} [{}]",
            ui::addr(message.port_queue.0),
            kind_name(message.port_queue_kind)
        ),
    );
    if let Some(owner) = message.port_queue_owner {
        row(
            "QueuePortOwnerProcess",
            owner_label(owner, &message.port_queue_owner_name),
        );
    }
    for field in &message.pointers {
        row(field.field, ui::addr(field.value.0));
    }
    row("CancelSequenceNumber", number(message.cancel_sequence_no));
    row("ExtensionBufferSize", number(message.extension_buffer_size));
    for field in &message.attributes {
        row(field.field, ui::addr(field.value.0));
    }
    outln!();
}

fn print_alpc_process_ports(ports: &AlpcProcessPorts) {
    let process = &ports.process;
    let label = format!(
        "{} ({}, PID {})",
        ui::addr(process.eprocess.0),
        process.name,
        process.pid
    );
    outln!("Ports created by the process {label}:");
    for port in &ports.created {
        outln!(
            "  {} ('{}') handle {:#x}, {} connection(s)",
            ui::addr(port.port.0),
            port.name.as_deref().unwrap_or(""),
            port.handle,
            port.connections.len()
        );
        port.connections.iter().for_each(print_alpc_connection);
        if let Some(why) = port.termination.diagnostic() {
            outln!("    connection list ended early: {why}");
        }
    }
    outln!();
    outln!("Ports the process {label} is connected to:");
    outln!("  (client port, queued -> server port, queued, server process; connection port)");
    for port in &ports.connected {
        outln!(
            "  {} {} -> {} {} {}  {} ('{}')  handle {:#x}",
            ui::addr(port.port.0),
            optional_count(port.queued),
            ui::addr(port.server_port.0),
            optional_count(port.server_queued),
            port.server_owner
                .map_or("-".to_string(), |owner| owner_label(
                    owner,
                    &port.server_owner_name
                )),
            ui::addr(port.connection_port.0),
            port.connection_name.as_deref().unwrap_or(""),
            port.handle
        );
    }
    outln!();
    outln!(
        "{} server communication port handle(s); scanned {}/{} handle slots{}",
        ports.server_ports,
        ports.scanned_handles,
        ports.advertised_handles,
        if ports.skipped_entries == 0 {
            String::new()
        } else {
            format!(", {} unreadable", ports.skipped_entries)
        }
    );
    outln!();
}

fn print_zombies(detail: &Zombies) {
    let exited = |filetime: u64| {
        format_filetime_precise(filetime).unwrap_or_else(|| format!("{filetime:#x}"))
    };
    if detail.kinds.processes {
        outln!(
            "Zombie processes: {} (and {} live process object(s) seen)",
            detail.processes.len(),
            detail.live_processes
        );
        if !detail.processes.is_empty() {
            outln!(
                "  {:<16}  {:>6}  {:<15}  {:<28}  {:<10}  {:>7}  {:>8}",
                "EPROCESS",
                "PID",
                "Image",
                "Exited",
                "Status",
                "Handles",
                "Pointers"
            );
        }
        for process in &detail.processes {
            outln!(
                "  {}  {:>6}  {:<15}  {:<28}  {:#010x}  {:>7}  {:>8}",
                ui::addr(process.eprocess.0),
                process.pid,
                process.image,
                exited(process.exit_time),
                process.exit_status,
                process.handle_count,
                process.pointer_count
            );
        }
    }
    if detail.kinds.threads {
        outln!(
            "Zombie threads: {} (and {} live thread object(s) seen)",
            detail.threads.len(),
            detail.live_threads
        );
        if !detail.threads.is_empty() {
            outln!(
                "  {:<16}  {:<13}  {:<16}  {:<15}  {:<10}  {:>7}  {:>8}",
                "ETHREAD",
                "Cid",
                "Process",
                "Image",
                "Status",
                "Handles",
                "Pointers"
            );
        }
        for thread in &detail.threads {
            outln!(
                "  {}  {:<13}  {}  {:<15}  {:#010x}  {:>7}  {:>8}",
                ui::addr(thread.ethread.0),
                format!("{:x}.{:x}", thread.pid, thread.tid),
                ui::addr(thread.process.0),
                thread.image.as_deref().unwrap_or("?"),
                thread.exit_status,
                thread.handle_count,
                thread.pointer_count
            );
        }
    }
    let region = format!(
        "{} pages of nonpaged pool ({:#x} - {:#x}) scanned",
        detail.scanned_pages, detail.region_start.0, detail.region_end.0
    );
    if detail.interrupted {
        outln!("{region}; interrupted, so the lists are partial");
    } else if detail.truncated {
        outln!("{region}; stopped at {MAX_ZOMBIES} of one kind, so the lists are partial");
    } else {
        outln!("{region}");
    }
    outln!();
}
