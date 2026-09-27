//! Process-state inspectors: job objects, global flags, handle traces, and
//! ALPC ports.

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::alpc::{
    AlpcConnection, AlpcMessageDetail, AlpcPortDetail, AlpcPortKind, AlpcProcessPorts,
    lpc_message_type_name,
};
use crate::target::gflag::{GLOBAL_FLAGS, GlobalFlagChange, GlobalFlagsDetail, global_flags_set};
use crate::target::htrace::{HandleTraceDetail, handle_trace_kind_name};
use crate::target::job::{JobDetail, job_limit_flag_names};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_job;
    names: ["!job", "job"],
    usage: "!job [address [flags]]",
    summary: "Show a job object: accounting, limits, nesting, and its processes.",
    details: "The address is a job, or a process or thread whose job is shown; omitted or 0, the current process's job. Flags: 1 (the default) shows the job's accounting, limits, and flags; 2 lists the processes assigned to it (from ProcessListHead). Child jobs, the parent and root job, and silo state are shown with 1.",
    completion: Expression,
}

repl_command! {
    cmd_gflag;
    names: ["!gflag", "gflag"],
    usage: "!gflag [[+|-]value | {+|-}abbreviation | -?]",
    summary: "Show or change nt!NtGlobalFlag; also shows the current process's PEB flags.",
    details: "Without an argument, decodes nt!NtGlobalFlag and the current process's _PEB.NtGlobalFlag by the GFlags names. `+` sets and `-` clears the bits of a value or of one flag named by its three-letter abbreviation (`!gflag +ust`); a bare value replaces nt!NtGlobalFlag. A change is one 4-byte write to nt!NtGlobalFlag, as `ed` makes; the PEB copy is not changed. `-?` lists the flags and their abbreviations.",
    completion: Expression,
}

repl_command! {
    cmd_htrace;
    names: ["!htrace", "htrace"],
    usage: "!htrace [handle [process [max-traces]]]",
    summary: "Show the stacks handle tracing recorded for a process's handles.",
    details: "Reads the ring of traces (open, close, bad reference) in the process handle table's DebugInfo, newest first. Handle 0 or omitted shows every handle's traces; the process (an EPROCESS address, PID, or name) defaults to the current one. Tracing must already be on for the process (Application Verifier's Handles check, or NtSetInformationProcess(ProcessHandleTracing)); !htrace says when it is not. User-mode frames resolve once the process's modules are loaded (.process /p). The user-mode forms that change tracing (-enable, -disable, -snapshot, -diff) are not provided.",
    completion: Expression,
}

repl_command! {
    cmd_alpc;
    names: ["!alpc", "alpc"],
    usage: "!alpc /p <port> | /m <message> | /lpp [process]",
    summary: "Show an ALPC port, an ALPC message, or the ports a process holds.",
    details: "/p decodes an _ALPC_PORT (its object body or header): its kind, owner, the connection, server, and client ports of its communication info, its state flags, and its queues with the messages (or, for the wait queue, the threads) on them; a connection port also lists its connections. /m decodes a _KALPC_MESSAGE: its IDs, type, sizes, state, owner and queue ports, and the waiting and server threads. /lpp walks a process's handle table (an EPROCESS address, PID, or name; default the current process) for ALPC ports: the connection ports it owns with each connection's server and client ports and client process, then the ports it is connected to. The number after a port is its queued messages (main, large-message, and pending queues).",
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
                let process = match invocation.arg(1) {
                    Some(selector) => target.matching_processes(None).and_then(|processes| {
                        self.process_for_selector_or_name(selector, &processes)
                    }),
                    None => target.selected_process_info(),
                };
                match process.and_then(|process| target.alpc_process_ports(process)) {
                    Ok(ports) => print_alpc_process_ports(&ports),
                    Err(error) => error!("{error}"),
                }
            }
            _ => usage(),
        }
        Ok(())
    }

    fn cmd_htrace(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let arg = |index: usize| invocation.arg(index).filter(|text| *text != "0");
        let handle = match arg(0).map(|text| self.eval_or_report(text)) {
            Some(Some(VirtAddr(handle))) => Some(handle),
            Some(None) => return Ok(()),
            None => None,
        };
        let max_traces = match arg(2).map(|text| self.eval_or_report(text)) {
            Some(Some(VirtAddr(max))) => Some(max as usize),
            Some(None) => return Ok(()),
            None => None,
        };
        let target = &self.ctx.target;
        let process = match arg(1) {
            Some(selector) => target
                .matching_processes(None)
                .and_then(|processes| self.process_for_selector_or_name(selector, &processes)),
            None => target.selected_process_info(),
        };
        match process.and_then(|process| target.handle_traces(&process, handle, max_traces)) {
            Ok(detail) => print_handle_traces(&detail),
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
        let mut values = [None, Some(1)];
        for (slot, arg) in values.iter_mut().zip(&invocation.argv) {
            match self.eval_or_report(arg.as_ref()) {
                Some(VirtAddr(value)) => *slot = Some(value),
                None => return Ok(()),
            }
        }
        let [address, flags] = values;
        let target = &self.ctx.target;
        match target
            .job_address(address.map(VirtAddr))
            .and_then(|job| target.inspect_job(job))
        {
            Ok(job) => print_job(&job, flags.unwrap_or(1)),
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
        outln!(
            "  Job Flags ({})",
            job.job_flags
                .map_or("-".to_string(), |flags| format!("{flags:#x}"))
        );
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
        let job_link =
            |link: Option<VirtAddr>| link.map_or("-".to_string(), |link| ui::addr(link.0));
        outln!(
            "  Nesting: depth {}  parent {}  root {}",
            optional(job.nesting_depth),
            job_link(job.parent_job),
            job_link(job.root_job)
        );
        for child in &job.child_jobs {
            outln!("    child job {}", ui::addr(child.0));
        }
        if job.silo {
            outln!(
                "  Silo: ServerSiloGlobals {}",
                job_link(job.server_silo_globals)
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
            port.state_flags
                .iter()
                .map(|flag| format!("[{flag}]"))
                .collect::<Vec<_>>()
                .join(" ")
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
            message
                .state_flags
                .iter()
                .map(|flag| format!("[{flag}]"))
                .collect::<Vec<_>>()
                .join(" ")
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
