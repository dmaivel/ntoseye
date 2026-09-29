//! Process-state inspectors: job objects, global flags, handle traces, ALPC
//! ports, and exited processes and threads still referenced.

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::alpc::{
    AlpcConnection, AlpcMessageDetail, AlpcPortDetail, AlpcPortKind, AlpcProcessPorts,
    lpc_message_type_name,
};
use crate::target::etw::format_filetime_precise;
use crate::target::gflag::{GLOBAL_FLAGS, GlobalFlagChange, GlobalFlagsDetail, global_flags_set};
use crate::target::htrace::{HandleTraceDetail, handle_trace_kind_name};
use crate::target::job::{JobDetail, job_limit_flag_names};
use crate::target::zombies::{MAX_ZOMBIES, ZombieKinds, ZombiesDetail};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_job;
    names: ["!job", "job"],
    usage: "!job [address [flags]]",
    summary: "Show a job object and the processes in it.",
    details: "Shows a job object. The address can be a job, a process, or a thread. For a process or thread, the command shows its job. If you do not give an address, or give 0, the command shows the job of the current process. Flag 1 (the default) shows the accounting, limits, and flags of the job. Flag 1 also shows the child jobs, the parent and root job, and the silo state. Flag 2 lists the processes assigned to the job (from ProcessListHead).",
    completion: Expression,
}

repl_command! {
    cmd_gflag;
    names: ["!gflag", "gflag"],
    usage: "!gflag [[+|-]value | {+|-}abbreviation | -?]",
    summary: "Show or change nt!NtGlobalFlag, and show the PEB flags of the current process.",
    details: "Without an argument, the command decodes nt!NtGlobalFlag and the _PEB.NtGlobalFlag of the current process. It shows the bits by their GFlags names. `+` sets bits and `-` clears bits. The bits come from a value, or from one flag that you name by its three-letter abbreviation (`!gflag +ust`). A value without `+` or `-` replaces nt!NtGlobalFlag. Each change is one 4-byte write to nt!NtGlobalFlag, the same write that `ed` makes. The command does not change the PEB copy. `-?` lists the flags and their abbreviations.",
    completion: Expression,
}

repl_command! {
    cmd_zombies;
    names: ["!zombies", "zombies"],
    usage: "!zombies [flags]",
    summary: "List exited processes and threads that still have references.",
    details: "Scans nonpaged pool for process (`Proc`) and thread (`Thre`) objects. The command finds the header of each object by its decoded type. It lists the processes that have ExitTime set and the threads in the Terminated state. For each object, it shows the handle count and the pointer count. These counts show what keeps the object in memory. Flag 1 (the default) lists processes, 2 lists threads, and 3 lists both. The scan stops after 4096 processes or 4096 threads, or when you push Ctrl+C.",
    completion: Expression,
}

repl_command! {
    cmd_htrace;
    names: ["!htrace", "htrace"],
    usage: "!htrace [handle [process [max-traces]]]",
    summary: "Show the stacks that handle tracing recorded for the handles of a process.",
    details: "Reads the ring of traces (open, close, bad reference) in the DebugInfo of the process handle table. The command shows the newest trace first. If handle is 0 or not given, the command shows the traces of all handles. If max-traces is 0 or not given, it shows all traces. The process can be an EPROCESS address, a PID, or a name. The default is the current process. Handle tracing must be on for the process before you use the command. Tracing is on after the Handles check of Application Verifier, or after NtSetInformationProcess(ProcessHandleTracing). If tracing is off, !htrace shows a message. User-mode frames resolve after the modules of the process are loaded (.process /p). The command does not have the user-mode forms that change tracing (-enable, -disable, -snapshot, -diff).",
    completion: Expression,
}

repl_command! {
    cmd_alpc;
    names: ["!alpc", "alpc"],
    usage: "!alpc /p <port> | /m <message> | /lpp [process]",
    summary: "Show an ALPC port, an ALPC message, or the ports that a process holds.",
    details: "/p decodes an _ALPC_PORT from its object body or header. It shows the kind, owner, and state flags of the port. It also shows the connection, server, and client ports of its communication info. It shows the queues of the port and the messages on them. For the wait queue, it shows the threads. For a connection port, /p also lists the connections. /m decodes a _KALPC_MESSAGE. It shows the IDs, type, sizes, and state of the message, and its owner and queue ports. It also shows the waiting and server threads. /lpp walks the handle table of a process to find ALPC ports. The process can be an EPROCESS address, a PID, or a name. The default is the current process. /lpp first shows the connection ports that the process owns. For each connection, it shows the server and client ports and the client process. Then /lpp shows the ports that the process is connected to. The number after a port is the count of its queued messages in the main, large-message, and pending queues.",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_alpc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let usage = || error!("usage: !alpc /p <port> | /m <message> | /lpp [process]");
        let Some(switch) = invocation.arg(0) else {
            usage();
            return Ok(());
        };
        let target = &self.ctx.target;
        match switch.to_ascii_lowercase().as_str() {
            form @ ("/p" | "/m") => {
                let Some(text) = invocation.arg(1) else {
                    usage();
                    return Ok(());
                };
                let Some(address) = self.eval_or_report(text) else {
                    return Ok(());
                };
                let target = &self.ctx.target;
                let shown = if form == "/p" {
                    target.alpc_port(address).map(|port| print_alpc_port(&port))
                } else {
                    target
                        .alpc_message(address)
                        .map(|message| print_alpc_message(&message))
                };
                if let Err(error) = shown {
                    error!("{error}");
                }
            }
            "/lpp" => {
                match self
                    .process_or_current(invocation.arg(1))
                    .and_then(|process| target.alpc_process_ports(process))
                {
                    Ok(ports) => print_alpc_process_ports(&ports),
                    Err(error) => error!("{error}"),
                }
            }
            _ => usage(),
        }
        Ok(())
    }

    fn cmd_htrace(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // A handle or max-traces of 0, like an omitted one, means all.
        let mut values = [None; 2];
        for (slot, index) in values.iter_mut().zip([0, 2]) {
            if let Some(text) = invocation.arg(index) {
                let Some(VirtAddr(value)) = self.eval_or_report(text) else {
                    return Ok(());
                };
                *slot = (value != 0).then_some(value);
            }
        }
        let [handle, max_traces] = values;
        let target = &self.ctx.target;
        match self
            .process_or_current(invocation.arg(1).filter(|text| *text != "0"))
            .and_then(|process| {
                target.handle_traces(&process, handle, max_traces.map(|max| max as usize))
            }) {
            Ok(detail) => print_handle_traces(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_zombies(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let flags = match invocation.arg(0).map(|text| self.eval_or_report(text)) {
            Some(Some(VirtAddr(flags))) => flags,
            Some(None) => return Ok(()),
            None => 1,
        };
        match ZombieKinds::from_flags(flags).and_then(|kinds| self.ctx.target.zombies(kinds)) {
            Ok(detail) => print_zombies(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_gflag(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let target = &self.ctx.target;
        match invocation.arg(0) {
            Some("-?") => {
                for flag in &GLOBAL_FLAGS {
                    outln!(
                        "  {:#010x} {:<3} {}",
                        flag.bit,
                        flag.abbreviation,
                        flag.description
                    );
                }
                outln!();
                return Ok(());
            }
            Some(text) => {
                let change = GlobalFlagChange::parse(text, |text| {
                    Expr::eval_with_radix(text, target, self.radix).map(|value| value.0)
                });
                match change.and_then(|change| target.change_global_flag(change)) {
                    Ok((old, new)) => outln!("NtGlobalFlag {old:#010x} -> {new:#010x}"),
                    Err(error) => {
                        error!("{error}");
                        return Ok(());
                    }
                }
            }
            None => {}
        }
        match target.global_flags() {
            Ok(detail) => print_global_flags(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_job(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut values = [0, 1];
        for (slot, arg) in values.iter_mut().zip(&invocation.argv) {
            match self.eval_or_report(arg.as_ref()) {
                Some(VirtAddr(value)) => *slot = value,
                None => return Ok(()),
            }
        }
        let [address, flags] = values;
        let target = &self.ctx.target;
        match target
            .job_address(Some(VirtAddr(address)))
            .and_then(|job| target.inspect_job(job))
        {
            Ok(job) => print_job(&job, flags),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

fn print_job(job: &JobDetail, flags: u64) {
    outln!("Job at {}", ui::addr(job.address.0));
    let optional = |value: Option<u64>| value.map_or("-".to_string(), |value| value.to_string());
    outln!(
        "  JobId {}  SessionId {}",
        optional(job.job_id),
        optional(job.session_id)
    );
    if flags & 1 != 0 {
        outln!("  Basic Accounting Information");
        for field in &job.accounting {
            outln!("    {:<28} {:#x}", format!("{}:", field.field), field.value);
        }
        outln!("  Job Flags ({})", optional_hex(job.job_flags));
        for name in &job.job_flag_names {
            outln!("    [{name}]");
        }
        outln!("  Limit Information");
        for field in &job.limits {
            let names = if field.field.ends_with("LimitFlags") {
                format!(" {}", job_limit_flag_names(field.value).join(" "))
            } else {
                String::new()
            };
            outln!(
                "    {:<28} {:#x}{names}",
                format!("{}:", field.field),
                field.value
            );
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
        if let Some(why) = job.child_job_termination.diagnostic() {
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
                ui::addr(process.eprocess_va.0),
                process.pid,
                process.name
            );
        }
        for eprocess in &job.unreadable_processes {
            outln!("    PROCESS {}  (unreadable)", ui::addr(eprocess.0));
        }
        if let Some(why) = job.process_termination.diagnostic() {
            outln!("    process list ended early: {why}");
        }
    }
    outln!();
}

fn print_global_flags(detail: &GlobalFlagsDetail) {
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

fn print_handle_traces(detail: &HandleTraceDetail) {
    let process = &detail.process;
    outln!(
        "Process {} ({}, PID {})",
        ui::addr(process.eprocess_va.0),
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
        outln!(
            "Handle {:#x} - {}:",
            trace.handle,
            handle_trace_kind_name(trace.kind)
        );
        outln!(
            "Thread ID = {:#x}, Process ID = {:#x}",
            trace.thread_id,
            trace.process_id
        );
        for (address, symbol) in &trace.stack {
            match symbol {
                Some(symbol) => outln!("{}: {}", ui::addr(address.0), ui::symbol(symbol)),
                None => outln!("{}", ui::addr(address.0)),
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
    kind.map_or("unknown", AlpcPortKind::name)
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

fn print_alpc_port(port: &AlpcPortDetail) {
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

fn print_alpc_message(message: &AlpcMessageDetail) {
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
        ui::addr(process.eprocess_va.0),
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

fn print_zombies(detail: &ZombiesDetail) {
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
                process.counts.handle_count,
                process.counts.pointer_count
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
                thread.counts.handle_count,
                thread.counts.pointer_count
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
