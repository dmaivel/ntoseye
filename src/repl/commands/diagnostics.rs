use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::{DiagnosticMetric, DiagnosticValue, ListTermination, ResourceDetail};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_handle;
    names: ["!handle"],
    usage: "!handle [handle-expression]",
    summary: "List bounded handles for the selected process, or inspect one handle.",
    details: "Without an argument, scans at most 256 handle-table slots. The detail form reports the object, type, name, access mask, and attributes when decodable.",
    completion: Expression,
}

repl_command! {
    cmd_token();
    names: ["!token"],
    usage: "!token",
    summary: "Inspect the selected/current process primary token.",
    details: "Reports independently available token IDs, user/groups, privileges, type, impersonation level, and flags. Missing metadata or memory is shown per field.",
}

repl_command! {
    cmd_fileobj;
    names: ["!fileobj"],
    usage: "!fileobj <address-expression>",
    summary: "Decode a FILE_OBJECT and its device/name relationships.",
    completion: Expression,
}

repl_command! {
    cmd_locks;
    names: ["!locks"],
    usage: "!locks [resource-address-expression]",
    summary: "Inspect one ERESOURCE, or enumerate the symbol-backed resource list.",
    details: "The no-argument form uses ExpSystemResourcesList and is bounded to 256 entries. It never scans memory; if the symbol/list metadata is absent, enumeration is unavailable.",
    completion: Expression,
}

repl_command! {
    cmd_memusage;
    names: ["!memusage"],
    usage: "!memusage [process-limit]",
    summary: "Show bounded system and per-process memory-use counters.",
    details: "Uses validated memory-manager globals, KDBG fields, or recognized public getter code plus EPROCESS.Vm counters. It does not scan physical memory or walk every VAD.",
    completion: Expression,
}

fn diagnostic_cell<T: Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_metric_cell<T: Display>(metric: &DiagnosticMetric<T>) -> String {
    match metric.source {
        Some(source) => format!("{} [{source}]", diagnostic_cell(&metric.value)),
        None => diagnostic_cell(&metric.value),
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

fn diagnostic_status(value: &DiagnosticValue<i32>) -> String {
    match value {
        DiagnosticValue::Available(value) => format!("{:#010x}", *value as u32),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_addr(value: &DiagnosticValue<VirtAddr>) -> String {
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

fn print_resource(detail: &ResourceDetail) {
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

fn parse_expression(
    state: &ReplState<'_>,
    expression: &str,
) -> std::result::Result<VirtAddr, String> {
    Expr::eval_with_radix(expression, &state.ctx.target, state.radix)
        .map_err(|error| error.to_string())
}

impl ReplState<'_> {
    fn cmd_handle(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(expression) = invocation.arg(0) {
            let handle = match parse_expression(self, expression) {
                Ok(value) => value.0,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            };
            match self.ctx.target.inspect_handle(handle) {
                Ok(detail) => {
                    outln!(
                        "handle {:#x}  entry {}",
                        detail.handle,
                        ui::addr(detail.entry.0)
                    );
                    outln!("  object      : {}", diagnostic_addr(&detail.object));
                    outln!(
                        "  type        : {}",
                        diagnostic_opt_string(&detail.type_name)
                    );
                    outln!("  name        : {}", diagnostic_opt_string(&detail.name));
                    outln!("  access      : {}", diagnostic_hex(&detail.granted_access));
                    outln!("  attributes  : {}", diagnostic_hex(&detail.attributes));
                }
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }

        match self.ctx.target.enumerate_handles(256) {
            Ok(summary) => {
                outln!(
                    "handles: {} ({})  table {} level {}  scanned {}/{} slots, {} skipped{}",
                    summary.process.name,
                    summary.process.pid,
                    ui::addr(summary.table.0),
                    summary.table_level,
                    summary.scanned_handles,
                    summary.advertised_handles,
                    summary.skipped_entries,
                    if summary.truncated { " (bounded)" } else { "" }
                );
                let mut builder = Builder::default();
                builder.push_record(["Handle", "Object", "Type", "Access", "Name"]);
                for entry in summary.entries {
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
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_token(&mut self) -> Result<()> {
        match self.ctx.target.inspect_process_token() {
            Ok(token) => {
                outln!(
                    "token: {} ({})  {}",
                    token.process.name,
                    token.process.pid,
                    ui::addr(token.token.0)
                );
                outln!("  token id           : {}", diagnostic_hex(&token.token_id));
                outln!(
                    "  authentication id  : {}",
                    diagnostic_hex(&token.authentication_id)
                );
                outln!(
                    "  type               : {}",
                    diagnostic_cell(&token.token_type)
                );
                outln!(
                    "  impersonation      : {}",
                    diagnostic_cell(&token.impersonation_level)
                );
                outln!("  flags              : {}", diagnostic_hex(&token.flags));
                match &token.user {
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
                match &token.groups {
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
                match &token.privileges {
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
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_fileobj(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expression = require_arg!(invocation, 0, "!fileobj");
        let address = match parse_expression(self, expression) {
            Ok(address) => address,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        match self.ctx.target.inspect_file_object(address) {
            Ok(file) => {
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
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_locks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(expression) = invocation.arg(0) {
            let address = match parse_expression(self, expression) {
                Ok(address) => address,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            };
            match self.ctx.target.inspect_resource(address) {
                Ok(detail) => print_resource(&detail),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }

        match self.ctx.target.enumerate_resources(256) {
            Ok(summary) => {
                outln!(
                    "executive resources: head {} entries {} termination {}",
                    ui::addr(summary.head.0),
                    summary.resources.len(),
                    match summary.termination {
                        ListTermination::Head => "head".to_string(),
                        ListTermination::Null => "null (corrupt)".to_string(),
                        ListTermination::Cycle(address) => {
                            format!("cycle at {} (corrupt)", ui::addr(address.0))
                        }
                        ListTermination::Bound => "bound (truncated)".to_string(),
                        ListTermination::Corrupt(error) => format!("read error: {error}"),
                    }
                );
                for detail in &summary.resources {
                    print_resource(detail);
                }
            }
            Err(error) => error!("global resource enumeration unavailable: {error}"),
        }
        Ok(())
    }

    fn cmd_memusage(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let limit = match invocation.arg(0) {
            Some(expression) => match parse_expression(self, expression) {
                Ok(value) => value.0 as usize,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
            },
            None => 64,
        };
        match self.ctx.target.memory_use_summary(limit) {
            Ok(summary) => {
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
                let mut builder = Builder::default();
                builder.push_record([
                    "PID",
                    "Process",
                    "Virtual",
                    "Working set",
                    "Pagefile",
                    "Private",
                ]);
                for process in summary.processes {
                    builder.push_record([
                        process.process.pid.to_string(),
                        process.process.name,
                        diagnostic_cell(&process.virtual_size),
                        diagnostic_cell(&process.working_set_size),
                        diagnostic_cell(&process.pagefile_usage),
                        diagnostic_cell(&process.private_usage),
                    ]);
                }
                print_padded_table(builder);
                if summary.truncated {
                    outln!(
                        "process list bounded: displayed {} of {}",
                        limit.clamp(1, 256),
                        summary.process_count
                    );
                }
            }
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::diagnostic_cell;
    use crate::target::DiagnosticValue;

    #[test]
    fn unavailable_fields_keep_the_exact_reason() {
        let field =
            DiagnosticValue::<u64>::Unavailable("Field 'PrivateUsage' not found".to_string());
        assert_eq!(
            diagnostic_cell(&field),
            "<unavailable: Field 'PrivateUsage' not found>"
        );
    }
}
