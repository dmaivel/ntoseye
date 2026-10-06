//! The listing commands as Tern tables: `lm`, `!process`/`ps`, `bl` and the
//! vCPU list. The name or symbol column carries each table and grows; the
//! secondary addresses and the rarely set columns hide first in a narrow
//! pane.

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Span, TableRow, TextAlign, Truncate};

use super::{MUTED, NUMBER, STRONG, addr, span, symbol};
use crate::breakpoints::{Breakpoint, BreakpointScope};
use crate::guest::ProcessInfo;
use crate::repl::commands::symbols::ModuleListing;
use crate::session::VcpuInfo;
use crate::symbols::ModuleSymbolStatus;
use crate::target::sched::ProcessDetail;
use crate::types::VirtAddr;

/// `-`, quiet, for a field that has no value.
fn none() -> Span {
    span("-", MUTED)
}

/// A pointer field in `style`, `-` when absent or null.
fn pointer(value: Option<VirtAddr>, style: &str) -> Span {
    match value.filter(|value| !value.is_zero()) {
        Some(value) => span(format!("{:016x}", value.0), style),
        None => none(),
    }
}

/// A decimal count, `-` when absent.
fn decimal(value: Option<u64>) -> Span {
    match value {
        Some(value) => span(value.to_string(), NUMBER),
        None => none(),
    }
}

/// A module's symbol state: loaded reads as success, a failure as an error,
/// anything else (none, skipped, still fetching, unknown) quiet.
fn symbol_status(status: Option<&ModuleSymbolStatus>) -> Span {
    match status {
        Some(status @ ModuleSymbolStatus::Loaded) => span(status.label(), "success"),
        Some(status @ ModuleSymbolStatus::Failed(_)) => span(status.label(), "error"),
        Some(status) => span(status.label(), MUTED),
        None => span("unknown", MUTED),
    }
}

/// `lm`: one row per module, the image path growing into the pane.
pub fn modules(modules: &[ModuleListing], timestamp: bool) -> View {
    let mut table = ui::table()
        .col(Column::new("start", "Start").priority(6.0))
        .col(Column::new("end", "End").priority(2.0))
        .col(Column::new("module", "Module").priority(10.0))
        .col(Column::new("version", "Version").priority(4.0))
        .col(Column::new("symbols", "Symbols").priority(8.0))
        .col(Column::new("source", "Source").priority(3.0));
    if timestamp {
        table = table.col(
            Column::new("timestamp", "Timestamp")
                .align(TextAlign::End)
                .priority(1.0),
        );
    }
    table = table.col(
        Column::new("image", "Image")
            .grow(1.0)
            .truncate(Truncate::Middle)
            .priority(5.0),
    );

    for listing in modules {
        let module = &listing.module;
        let mut row = TableRow::new(format!("{:x}", module.base_address.0))
            .cell("start", addr(module.base_address.0))
            .cell(
                "end",
                span(format!("{:016x}", module.end_address().0), MUTED),
            )
            .cell("module", span(&module.short_name, STRONG))
            .cell(
                "version",
                match module.file_version.as_deref() {
                    Some(version) => span(version, ""),
                    None => none(),
                },
            )
            .cell("symbols", symbol_status(listing.status.as_ref()))
            .cell(
                "source",
                match &listing.source {
                    Some(source) => span(source.label(), MUTED),
                    None => none(),
                },
            )
            .cell("image", span(&module.name, "path"));
        if timestamp {
            row = row.cell("timestamp", time_date_stamp(module.time_date_stamp));
        }
        table = table.row(row);
    }
    View::new().main([table])
}

fn time_date_stamp(stamp: Option<u32>) -> Span {
    match stamp {
        Some(stamp) => span(format!("{stamp:#x}"), NUMBER),
        None => none(),
    }
}

/// `lm v`: a section per module, its symbol details as key/value pairs.
pub fn module_details(modules: &[ModuleListing], timestamp: bool) -> View {
    let mut col = ui::col();
    for listing in modules {
        let module = &listing.module;
        let mut kv = ui::kv()
            .item(
                "range",
                [
                    addr(module.base_address.0),
                    span(" - ", MUTED),
                    addr(module.end_address().0),
                ],
            )
            .item("symbols", symbol_status(listing.status.as_ref()))
            .item(
                "source",
                match &listing.source {
                    Some(source) => span(source.label(), ""),
                    None => none(),
                },
            );
        kv = match listing.pdb {
            Some(identity) => kv
                .item("pdb guid", span(format!("{:032X}", identity.guid), NUMBER))
                .item("pdb age", span(identity.age.to_string(), NUMBER)),
            None => kv.item("pdb", none()),
        };
        if let Some(ModuleSymbolStatus::Failed(reason)) = &listing.status {
            kv = kv.item("error", span(reason, "error"));
        }
        if timestamp {
            kv = kv.item("timestamp", time_date_stamp(module.time_date_stamp));
        }
        col = col.child(
            ui::section()
                .head([
                    span(&module.short_name, STRONG),
                    span(format!("  {}", module.name), "muted path"),
                ])
                .collapsible(true)
                .child(kv),
        );
    }
    View::new().main([col])
}

/// `!process`: a row per process with its `_EPROCESS` fields, the image name
/// carrying the table. A field no process has gets no column.
pub fn processes(processes: &[ProcessInfo], details: &[ProcessDetail]) -> View {
    let any = |has: fn(&ProcessInfo, &ProcessDetail) -> bool| {
        processes
            .iter()
            .zip(details)
            .any(|(process, detail)| has(process, detail))
    };
    let optional = [
        (
            any(|_, detail| detail.session_id.is_some()),
            Column::new("session", "Session")
                .align(TextAlign::End)
                .priority(4.0),
        ),
        (
            any(|_, detail| detail.parent_pid.is_some()),
            Column::new("parent", "Parent")
                .align(TextAlign::End)
                .priority(6.0),
        ),
        (
            any(|_, detail| detail.handle_count.is_some()),
            Column::new("handles", "Handles")
                .align(TextAlign::End)
                .priority(5.0),
        ),
        (
            any(|_, detail| detail.peb.is_some_and(|peb| !peb.is_zero())),
            Column::new("peb", "Peb").priority(3.0),
        ),
        (
            any(|process, _| process.wow64_peb.is_some_and(|peb| !peb.is_zero())),
            Column::new("wow64", "Wow64").priority(1.0),
        ),
        (
            any(|_, detail| detail.directory_table_base.is_some()),
            Column::new("dirbase", "DirBase").priority(2.0),
        ),
        (
            any(|_, detail| detail.object_table.is_some_and(|table| !table.is_zero())),
            Column::new("objects", "ObjectTable").priority(1.0),
        ),
    ];
    let mut table = ui::table()
        .col(
            Column::new("pid", "PID")
                .align(TextAlign::End)
                .priority(9.0),
        )
        .col(
            Column::new("image", "Image")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(10.0),
        )
        .col(Column::new("eprocess", "EPROCESS").priority(7.0));
    for (shown, column) in optional {
        if shown {
            table = table.col(column);
        }
    }
    for (process, detail) in processes.iter().zip(details) {
        table = table.row(
            TableRow::new(format!("{:x}", process.eprocess_va.0))
                .cell("pid", span(process.pid.to_string(), NUMBER))
                .cell("image", span(&process.name, STRONG))
                .cell("eprocess", pointer(Some(process.eprocess_va), MUTED))
                .cell("session", decimal(detail.session_id.map(u64::from)))
                .cell("parent", decimal(detail.parent_pid))
                .cell("handles", decimal(detail.handle_count))
                .cell("peb", pointer(detail.peb, MUTED))
                .cell("wow64", pointer(process.wow64_peb, MUTED))
                .cell(
                    "dirbase",
                    pointer(detail.directory_table_base.map(VirtAddr), MUTED),
                )
                .cell("objects", pointer(detail.object_table, MUTED)),
        );
    }
    View::new().main([table])
}

/// `ps`: name, PID, `_EPROCESS`, page-table root and WOW64.
pub fn ps(processes: &[ProcessInfo]) -> View {
    let mut table = ui::table()
        .col(
            Column::new("name", "Name")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(10.0),
        )
        .col(
            Column::new("pid", "PID")
                .align(TextAlign::End)
                .priority(9.0),
        )
        .col(Column::new("eprocess", "EPROCESS").priority(5.0))
        .col(Column::new("dtb", "DTB").priority(3.0))
        .col(Column::new("wow64", "Wow64").priority(4.0));
    for process in processes {
        table = table.row(
            TableRow::new(format!("{:x}", process.eprocess_va.0))
                .cell("name", span(&process.name, STRONG))
                .cell("pid", span(process.pid.to_string(), NUMBER))
                .cell(
                    "eprocess",
                    span(format!("{:016x}", process.eprocess_va.0), MUTED),
                )
                .cell("dtb", span(format!("{:016x}", process.dtb), MUTED))
                .cell(
                    "wow64",
                    if process.is_wow64() {
                        span("x86", "info")
                    } else {
                        none()
                    },
                ),
        );
    }
    View::new().main([table])
}

/// `bl`: a row per breakpoint, its state colored, the site carrying the
/// table and the condition and command hiding first.
pub fn breakpoints(breakpoints: &[&Breakpoint]) -> View {
    // Columns no breakpoint uses go: a pass count, a process or thread
    // filter, a condition, a command.
    let any = |has: fn(&Breakpoint) -> bool| breakpoints.iter().any(|bp| has(bp));
    let mut table = ui::table()
        .col(Column::new("id", "ID").align(TextAlign::End).priority(9.0))
        .col(Column::new("state", "State").priority(8.0))
        .col(Column::new("address", "Address").priority(5.0))
        .col(
            Column::new("site", "Symbol")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(10.0),
        );
    if any(|bp| bp.pass_count > 1 || bp.remaining_pass_count > 0) {
        table = table.col(
            Column::new("passes", "Passes")
                .align(TextAlign::End)
                .priority(2.0),
        );
    }
    if any(|bp| !unscoped(bp)) {
        table = table.col(Column::new("scope", "Process/Thread").priority(4.0));
    }
    if any(|bp| bp.condition.is_some()) {
        table = table.col(
            Column::new("condition", "Condition")
                .truncate(Truncate::End)
                .priority(1.0),
        );
    }
    if any(|bp| bp.action.is_some()) {
        table = table.col(
            Column::new("action", "Action")
                .truncate(Truncate::End)
                .priority(1.0),
        );
    }
    for bp in breakpoints {
        // `pending`: enabled and accepted by the target, but the opcode is
        // owed until its page is resident (the text list's `o`).
        let state = match (bp.enabled, bp.awaiting_page_in()) {
            (true, true) => span("pending", "warning"),
            (true, false) => span("enabled", "success"),
            (false, _) => span("disabled", MUTED),
        };
        let site = bp.specification().or(bp.symbol.as_deref());
        let mut site_spans = Vec::new();
        if let Some(hw) = bp.hardware {
            site_spans.push(span(
                format!("watch {}{} ", hw.access.letter(), hw.len),
                MUTED,
            ));
        }
        match site {
            Some(site) => site_spans.extend(symbol(site)),
            None => site_spans.push(none()),
        }
        let optional = |text: Option<&str>| match text {
            Some(text) => span(text, ""),
            None => none(),
        };
        table = table.row(
            TableRow::new(bp.id.to_string())
                .cell("id", span(format!("#{}", bp.id), "info"))
                .cell("state", state)
                .cell(
                    "address",
                    match bp.resolved_address() {
                        Some(address) => addr(address.0),
                        None => none(),
                    },
                )
                .cell("site", site_spans)
                .cell(
                    "passes",
                    [
                        span(
                            bp.remaining_pass_count.saturating_add(1).to_string(),
                            NUMBER,
                        ),
                        span(format!(" ({})", bp.pass_count.max(1)), MUTED),
                    ],
                )
                .cell("scope", span(bp.scope_label(), ""))
                .cell("condition", optional(bp.condition.as_deref()))
                .cell("action", optional(bp.action.as_deref())),
        );
    }
    View::new().main([table])
}

/// The vCPU list: what each vCPU runs, and below a vCPU in the hypervisor
/// where its VTLs left off and the guest VP it serves.
pub fn vcpus(vcpus: &[VcpuInfo]) -> View {
    let mut table = ui::table()
        .col(Column::new("vcpu", "vCPU").priority(9.0))
        .col(Column::new("rip", "RIP").priority(5.0))
        .col(Column::new("context", "Context").priority(7.0))
        .col(
            Column::new("symbol", "Symbol")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(10.0),
        );
    for vcpu in vcpus {
        let (rip, site) = match vcpu.rip {
            Some(rip) => (
                addr(rip),
                match &vcpu.symbol {
                    Some(name) => symbol(name),
                    None => symbol(&format!("{rip:#x}")),
                },
            ),
            None => (
                span("unavailable", MUTED),
                vec![span(vcpu.error.as_deref().unwrap_or_default(), "error")],
            ),
        };
        table = table.row(
            TableRow::new(vcpu.id.clone())
                .cell("vcpu", span(&vcpu.id, "info"))
                .cell("rip", rip)
                .cell("context", span(&vcpu.context, STRONG))
                .cell("symbol", site),
        );
        for (index, saved) in vcpu
            .saved_vtl
            .iter()
            .filter(|saved| saved.summarized())
            .enumerate()
        {
            table = table.row(TableRow::new(format!("{}.saved{index}", vcpu.id)).cell(
                "symbol",
                [span("└ saved ", MUTED), span(saved.describe(), "")],
            ));
        }
        if let Some(served) = &vcpu.serving {
            let mut line = vec![
                span("└ serving ", MUTED),
                span(served.label(), STRONG),
                span(format!("  {}", served.place()), ""),
            ];
            if let Some(exit) = served.last_exit() {
                line.push(span(format!(", {exit}"), MUTED));
            }
            table = table.row(TableRow::new(format!("{}.serving", vcpu.id)).cell("symbol", line));
            if let Some(detail) = served.exit_detail() {
                table = table.row(
                    TableRow::new(format!("{}.hypercall", vcpu.id))
                        .cell("symbol", span(format!("   └ {detail}"), MUTED)),
                );
            }
        }
    }
    View::new().main([table])
}

/// A breakpoint any thread anywhere stops at: what `bl` labels `global`.
fn unscoped(bp: &Breakpoint) -> bool {
    bp.scope == BreakpointScope::Kernel
        && bp.partition.is_none()
        && bp.thread.is_none()
        && bp.processor.is_none()
        && bp.hypercall.is_none()
        && bp.vm_exit.is_none()
}
