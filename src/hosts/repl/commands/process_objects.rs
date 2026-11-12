//! Process-state inspectors: job objects, global flags, handle traces, ALPC
//! ports, and exited processes and threads still referenced.

use crate::base::error::Result;
use crate::base::time::filetime_to_iso_precise;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::guest::ProcessInfo;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::alpc::{
    AlpcConnection, AlpcMessage, AlpcPort, AlpcPortKind, AlpcProcessPorts, lpc_message_type_name,
};
use crate::nt::target::gflag::{GLOBAL_FLAGS, GlobalFlagChange, GlobalFlags, global_flags_set};
use crate::nt::target::htrace::HandleTraces;
use crate::nt::target::job::{Job, job_limit_flag_names};
use crate::nt::target::zombies::{MAX_ZOMBIES, ZombieKinds, Zombies};
use crate::session::Session;
use ntoseye_macros::{command, grammar};
use tabled::builder::Builder;

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
#[command(form_of = alpc, python = Inspect)]
fn alpc_port(session: &Session, address: VirtAddr) -> Result<AlpcPort> {
    session.target.alpc_port(address)
}

/// Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
#[command(form_of = alpc, python = Inspect)]
fn alpc_message(session: &Session, address: VirtAddr) -> Result<AlpcMessage> {
    session.target.alpc_message(address)
}

/// Get the ALPC ports to which a process has handles (`!alpc /lpp`). The
/// result has the connection ports that the process owns, with their
/// connections, and the client ports through which the process is
/// connected. `process` defaults to the current process.
#[command(form_of = alpc, python = Inspect)]
fn alpc_process_ports(
    session: &Session,
    #[arg(positional)] process: Option<ProcessInfo>,
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

#[grammar(
    usage = "/p <port> | /m <message> | /lpp [process]",
    complete = [Expression, Expression]
)]
fn alpc_query(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AlpcQuery, ArgError> {
    let name = cx.name;
    let switch = cursor
        .word()
        .ok_or_else(|| ArgError::usage(name, format!("{name} needs /p, /m or /lpp")))?
        .to_ascii_lowercase();
    match switch.as_str() {
        form @ ("/p" | "/m") => {
            let address = cx.eval(&cursor.word().ok_or_else(|| {
                ArgError::usage(name, format!("{name} {form} needs an address"))
            })?)?;
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
        other => Err(ArgError::usage(
            name,
            format!("{name}: unknown switch '{other}'"),
        )),
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
)]
fn gflag(
    session: &Session,
    #[arg(render, switch = "-?")] list: bool,
    #[arg(name = "[+|-]value|+abbreviation|-abbreviation")] change: Option<GlobalFlagChange>,
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
#[command(form_of = gflag, python = Inspect, writes = [Memory])]
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
#[grammar(usage = "[{}]", complete = [Expression])]
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
                let abbreviation = if flag.abbreviation.is_empty() {
                    "-"
                } else {
                    flag.abbreviation
                };
                outln!(
                    "  {:#010x} {:<3} {}",
                    flag.bit,
                    abbreviation,
                    flag.description
                );
            }
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
    outln!("job {}", ui::addr(job.address.0));
    let optional = |value: Option<u64>| value.map_or("-".to_string(), |value| value.to_string());
    let mut fields = vec![
        ("JobId", optional(job.job_id)),
        ("SessionId", optional(job.session_id)),
    ];
    if flags & 1 != 0 {
        fields.push((
            "JobFlags",
            with_names(optional_hex(job.job_flags), &job.job_flag_names),
        ));
        fields.push(("NestingDepth", optional(job.nesting_depth)));
        fields.push(("ParentJob", optional_addr(job.parent_job)));
        fields.push(("RootJob", optional_addr(job.root_job)));
        if job.silo {
            fields.push(("ServerSiloGlobals", optional_addr(job.server_silo_globals)));
        }
    }
    print_fields(2, &fields);
    if flags & 1 != 0 {
        outln!("  Basic Accounting Information");
        let accounting: Vec<_> = job
            .accounting
            .fields()
            .filter_map(|(field, value)| Some((field, format!("{:#x}", value?))))
            .collect();
        print_fields(4, &accounting);
        outln!("  Limit Information");
        let limits: Vec<_> = job
            .limits
            .fields()
            .filter_map(|(field, value)| {
                let value = value?;
                let text = format!("{value:#x}");
                if !field.ends_with("LimitFlags") {
                    return Some((field, text));
                }
                // An unnamed bit comes back as its value, which the hex
                // value already shows, so only the named bits are listed.
                let names: Vec<String> = job_limit_flag_names(value)
                    .into_iter()
                    .filter(|name| !name.starts_with("0x"))
                    .collect();
                Some((field, with_names(text, &names)))
            })
            .collect();
        print_fields(4, &limits);
        let child_list_end = job.child_job_list_termination.diagnostic();
        if !job.child_jobs.is_empty() || child_list_end.is_some() {
            outln!("  Child Jobs");
            for child in &job.child_jobs {
                outln!("    {}", ui::addr(child.0));
            }
            if let Some(why) = child_list_end {
                outln!("    child job list ended early: {why}");
            }
        }
    }
    if flags & 2 != 0 {
        outln!("  Processes assigned to this job");
        let mut rows: Vec<[String; 3]> = job
            .processes
            .iter()
            .map(|process| {
                [
                    process.pid.to_string(),
                    process.name.clone(),
                    ui::addr(process.eprocess.0),
                ]
            })
            .collect();
        rows.extend(
            job.unreadable_processes
                .iter()
                .map(|eprocess| ["-".to_string(), "-".to_string(), ui::addr(eprocess.0)]),
        );
        // The rows sit inside the job's block, which print_padded_table
        // cannot indent, so the columns are padded here.
        let width = |column: usize, header: &str| {
            rows.iter()
                .map(|row| row[column].len())
                .max()
                .unwrap_or(0)
                .max(header.len())
        };
        let (pid_width, name_width) = (width(0, "PID"), width(1, "Name"));
        outln!(
            "    {:<pid_width$}  {:<name_width$}  EPROCESS",
            "PID",
            "Name"
        );
        for [pid, name, eprocess] in &rows {
            outln!("    {pid:<pid_width$}  {name:<name_width$}  {eprocess}");
        }
        if !job.unreadable_processes.is_empty() {
            outln!(
                "    {} on the list could not be read",
                counted(job.unreadable_processes.len(), "process", "processes")
            );
        }
        if let Some(why) = job.process_list_termination.diagnostic() {
            outln!("    process list ended early: {why}");
        }
    }
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
}

fn print_handle_traces(detail: &HandleTraces) {
    let process = &detail.process;
    outln!(
        "PROCESS {}  PID {}  {}",
        ui::addr(process.eprocess.0),
        process.pid,
        process.name
    );
    let object_table = ("ObjectTable", ui::addr(detail.object_table.0));
    let Some(debug_info) = detail.debug_info else {
        print_fields(2, &[object_table]);
        outln!(
            "handle tracing is off for {}: the Handles check of Application Verifier or NtSetInformationProcess(ProcessHandleTracing) turns it on",
            process.name
        );
        return;
    };
    print_fields(
        2,
        &[
            object_table,
            ("DebugInfo", ui::addr(debug_info.0)),
            ("TableSize", format!("{:#x}", detail.table_size)),
            ("CurrentStackIndex", format!("{:#x}", detail.recorded)),
        ],
    );
    // The trace records below keep WinDbg's !htrace layout, separators and
    // unnumbered `address: symbol` frames included.
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
    let traces = |count: u64| {
        let noun = if count == 1 { "trace" } else { "traces" };
        format!("{count:#x} stack {noun}")
    };
    outln!("Parsed {}", traces(detail.parsed));
    outln!("Dumped {}", traces(detail.traces.len() as u64));
    if detail.unreadable != 0 {
        let noun = if detail.unreadable == 1 {
            "slot"
        } else {
            "slots"
        };
        outln!("{:#x} trace {noun} unreadable", detail.unreadable);
    }
}

/// Prints `Name : value` fields at `indent`, with the colons in one column.
fn print_fields(indent: usize, fields: &[(&str, String)]) {
    let width = fields.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, value) in fields {
        outln!("{:indent$}{name:<width$} : {value}", "");
    }
}

/// A flag set: `value (A | B)`, or `value` alone when no names are set.
fn with_names(value: String, names: &[String]) -> String {
    if names.is_empty() {
        value
    } else {
        format!("{value} ({})", names.join(" | "))
    }
}

/// `1 connection`, `2 connections`.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn optional_addr(value: Option<VirtAddr>) -> String {
    value.map_or("-".to_string(), addr_or_dash)
}

/// A null pointer is no object, so it shows as `-`.
fn addr_or_dash(value: VirtAddr) -> String {
    if value.0 == 0 {
        "-".to_string()
    } else {
        ui::addr(value.0)
    }
}

fn optional_hex(value: Option<u64>) -> String {
    value.map_or("-".to_string(), |value| format!("{value:#x}"))
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or("-".to_string(), |value| value.to_string())
}

/// `address (image)`, or the address alone when the image name is unknown.
fn owner_label(owner: VirtAddr, name: &Option<String>) -> String {
    match name {
        Some(name) if owner.0 != 0 => format!("{} ({name})", ui::addr(owner.0)),
        _ => addr_or_dash(owner),
    }
}

/// `address (kind)`, or the address alone when the port kind is unknown.
fn port_label(port: VirtAddr, kind: Option<AlpcPortKind>) -> String {
    match kind {
        Some(kind) if port.0 != 0 => format!("{} ({kind})", ui::addr(port.0)),
        _ => addr_or_dash(port),
    }
}

/// ` ('name')`, or nothing for an unnamed port.
fn quoted_name(name: &Option<String>) -> String {
    name.as_ref()
        .map_or(String::new(), |name| format!(" ('{name}')"))
}

fn print_alpc_connection(indent: usize, connection: &AlpcConnection) {
    // An entry the walk could not read has no ports; the line saying why
    // the list ended early follows it.
    if connection.server_port.0 == 0 && connection.client_port.0 == 0 {
        return;
    }
    outln!(
        "{:indent$}{} {} -> {} {} {}",
        "",
        addr_or_dash(connection.server_port),
        optional_count(connection.server_queued),
        addr_or_dash(connection.client_port),
        optional_count(connection.client_queued),
        owner_label(connection.client_owner, &connection.client_owner_name)
    );
}

fn print_alpc_port(port: &AlpcPort) {
    outln!(
        "port {}{}",
        ui::addr(port.address.0),
        quoted_name(&port.name)
    );
    let port_type = match (port.kind, port.port_type) {
        (Some(kind), Some(bits)) => format!("{kind} ({bits:#x})"),
        (Some(kind), None) => kind.to_string(),
        (None, bits) => optional_hex(bits),
    };
    print_fields(
        2,
        &[
            ("Type", port_type),
            ("PointerCount", port.pointer_count.to_string()),
            ("HandleCount", port.handle_count.to_string()),
            ("OwnerProcess", owner_label(port.owner, &port.owner_name)),
            ("SequenceNo", optional_hex(port.sequence_no)),
            ("CompletionPort", optional_addr(port.completion_port)),
            ("CompletionList", optional_addr(port.completion_list)),
            ("PortContext", optional_addr(port.port_context)),
            ("PortAttributes.Flags", optional_hex(port.attribute_flags)),
            ("MaxMessageLength", optional_hex(port.max_message_length)),
            (
                "State",
                with_names(optional_hex(port.state), &port.state_flags),
            ),
        ],
    );
    outln!(
        "  CommunicationInfo {}",
        addr_or_dash(port.communication_info)
    );
    print_fields(
        4,
        &[
            ("ConnectionPort", optional_addr(port.connection_port)),
            ("ServerCommunicationPort", optional_addr(port.server_port)),
            ("ClientCommunicationPort", optional_addr(port.client_port)),
        ],
    );
    print_section("queues");
    let width = port
        .queues
        .iter()
        .map(|queue| queue.field.len())
        .chain(["DirectQueue".len()])
        .max()
        .unwrap_or(0);
    for queue in &port.queues {
        let entries = if queue.key == "wait" {
            counted(queue.entries.len(), "thread", "threads")
        } else {
            counted(queue.entries.len(), "message", "messages")
        };
        outln!(
            "  {:<width$}  {entries}, length {}",
            queue.field,
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
        "  {:<width$}  length {}",
        "DirectQueue",
        optional_count(port.direct_queue_length)
    );
    if let Some(termination) = &port.connection_termination {
        print_section(&format!("connections ({})", port.connections.len()));
        if !port.connections.is_empty() {
            outln!(
                "  {}",
                ui::muted("(server port, queued -> client port, queued, client process)")
            );
        }
        for connection in &port.connections {
            print_alpc_connection(2, connection);
        }
        if let Some(why) = termination.diagnostic() {
            outln!("  connection list ended early: {why}");
        }
    }
}

fn print_alpc_message(message: &AlpcMessage) {
    outln!("message {}", ui::addr(message.address.0));
    let number =
        |value: Option<u64>| value.map_or("-".to_string(), |value| format!("{value:#x} ({value})"));
    let message_type = match message.message_type {
        Some(value) => match lpc_message_type_name(value) {
            Some(name) => format!("{name} ({value:#x})"),
            None => format!("{value:#x}"),
        },
        None => "-".to_string(),
    };
    let mut fields = vec![
        ("MessageID", number(message.message_id)),
        ("CallbackID", number(message.callback_id)),
        ("SequenceNumber", number(message.sequence_no)),
        ("Type", message_type),
        ("DataLength", number(message.data_length)),
        ("TotalLength", number(message.total_length)),
        (
            "ClientId",
            format!(
                "{}.{}",
                optional_hex(message.client_process_id),
                optional_hex(message.client_thread_id)
            ),
        ),
        (
            "State",
            with_names(optional_hex(message.state), &message.state_flags),
        ),
        ("QueueType", optional_count(message.queue_type)),
        ("QueuePortType", optional_count(message.queue_port_type)),
        (
            "OwnerPort",
            port_label(message.owner_port, message.owner_port_kind),
        ),
        (
            "QueuePort",
            port_label(message.port_queue, message.port_queue_kind),
        ),
    ];
    if let Some(owner) = message.port_queue_owner {
        fields.push((
            "QueuePortOwnerProcess",
            owner_label(owner, &message.port_queue_owner_name),
        ));
    }
    for field in &message.pointers {
        fields.push((field.field, addr_or_dash(field.value)));
    }
    fields.push(("CancelSequenceNumber", number(message.cancel_sequence_no)));
    fields.push(("ExtensionBufferSize", number(message.extension_buffer_size)));
    for field in &message.attributes {
        fields.push((field.field, addr_or_dash(field.value)));
    }
    print_fields(2, &fields);
}

fn print_alpc_process_ports(ports: &AlpcProcessPorts) {
    let process = &ports.process;
    let label = format!(
        "{} (PID {}), EPROCESS {}",
        process.name,
        process.pid,
        ui::addr(process.eprocess.0)
    );
    // The first title is the first line, so it skips print_section's blank.
    outln!("{}", ui::label(&format!("ports created by {label}")));
    if ports.created.is_empty() {
        outln!("  {}", ui::muted("no connection ports"));
    }
    for port in &ports.created {
        outln!(
            "  {}{}  handle {:#x}, {}",
            ui::addr(port.port.0),
            quoted_name(&port.name),
            port.handle,
            counted(port.connections.len(), "connection", "connections")
        );
        for connection in &port.connections {
            print_alpc_connection(4, connection);
        }
        if let Some(why) = port.termination.diagnostic() {
            outln!("    connection list ended early: {why}");
        }
    }
    print_section(&format!(
        "ports {} (PID {}) is connected to",
        process.name, process.pid
    ));
    if ports.connected.is_empty() {
        outln!("  {}", ui::muted("no client ports"));
    } else {
        outln!(
            "  {}",
            ui::muted(
                "(client port, queued -> server port, queued, server process; connection port)"
            )
        );
    }
    for port in &ports.connected {
        outln!(
            "  {} {} -> {} {} {}  {}{}  handle {:#x}",
            addr_or_dash(port.port),
            optional_count(port.queued),
            addr_or_dash(port.server_port),
            optional_count(port.server_queued),
            port.server_owner
                .map_or("-".to_string(), |owner| owner_label(
                    owner,
                    &port.server_owner_name
                )),
            addr_or_dash(port.connection_port),
            quoted_name(&port.connection_name),
            port.handle
        );
    }
    outln!();
    outln!(
        "{}; scanned {} of {} handle slots{}{}",
        counted(
            ports.server_ports,
            "server communication port handle",
            "server communication port handles"
        ),
        ports.scanned_handles,
        ports.advertised_handles,
        if ports.skipped_entries == 0 {
            String::new()
        } else {
            format!(", {} unreadable", ports.skipped_entries)
        },
        if ports.unreadable_ports == 0 {
            String::new()
        } else {
            format!(", {} ALPC ports not decoded", ports.unreadable_ports)
        }
    );
}

fn print_zombies(detail: &Zombies) {
    let exited = |filetime: u64| {
        filetime_to_iso_precise(filetime).unwrap_or_else(|| format!("{filetime:#x}"))
    };
    let region = format!(
        "{} of nonpaged pool ({:#x} - {:#x}) scanned",
        counted(detail.scanned_pages as usize, "page", "pages"),
        detail.region_start.0,
        detail.region_end.0
    );
    if detail.interrupted {
        outln!("{region}; interrupted, so the lists are partial");
    } else if detail.truncated {
        outln!("{region}; stopped at {MAX_ZOMBIES} of one kind, so the lists are partial");
    } else {
        outln!("{region}");
    }
    // print_padded_table ends with a blank line, so the title of the
    // threads after the process table needs none of its own.
    let mut after_table = false;
    if detail.kinds.processes {
        print_section(&format!(
            "zombie processes ({}; {} live)",
            detail.processes.len(),
            detail.live_processes
        ));
        if detail.processes.is_empty() {
            outln!("  {}", ui::muted("no exited process is still referenced"));
        } else {
            let mut builder = Builder::default();
            builder.push_record([
                "PID", "Name", "EPROCESS", "Exited", "Status", "Handles", "Pointers",
            ]);
            for process in &detail.processes {
                builder.push_record([
                    process.pid.to_string(),
                    if process.image.is_empty() {
                        "-".to_string()
                    } else {
                        process.image.clone()
                    },
                    ui::addr(process.eprocess.0),
                    exited(process.exit_time),
                    format!("{:#010x}", process.exit_status),
                    process.handle_count.to_string(),
                    process.pointer_count.to_string(),
                ]);
            }
            print_padded_table(builder);
            after_table = true;
        }
    }
    if detail.kinds.threads {
        let title = format!(
            "zombie threads ({}; {} live)",
            detail.threads.len(),
            detail.live_threads
        );
        if after_table {
            outln!("{}", ui::label(&title));
        } else {
            print_section(&title);
        }
        if detail.threads.is_empty() {
            outln!(
                "  {}",
                ui::muted("no terminated thread is still referenced")
            );
        } else {
            let mut builder = Builder::default();
            builder.push_record([
                "TID", "PID", "Name", "ETHREAD", "EPROCESS", "Status", "Handles", "Pointers",
            ]);
            for thread in &detail.threads {
                builder.push_record([
                    thread.tid.to_string(),
                    thread.pid.to_string(),
                    thread.image.clone().unwrap_or_else(|| "-".to_string()),
                    ui::addr(thread.ethread.0),
                    ui::addr(thread.process.0),
                    format!("{:#010x}", thread.exit_status),
                    thread.handle_count.to_string(),
                    thread.pointer_count.to_string(),
                ]);
            }
            print_padded_table(builder);
        }
    }
}
