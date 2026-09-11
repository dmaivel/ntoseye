use owo_colors::OwoColorize;

use crate::bugchecks::{
    BUGCHECK_DATA_SLOTS, BugcheckFault, CurrentBugcheckFailure, CurrentBugcheckResolution,
    resolve_current_bugcheck,
};
use crate::dbg_backend::BugcheckInfo;
use crate::target::Target;
use crate::ui;

// Bugcheck *analysis* (descriptor lookup, fault site, KiBugCheckData decode)
// lives in core, shared with the SDK/MCP; the REPL adds presentation.
pub use crate::bugchecks::{
    BugcheckAnalysis, BugcheckTrapFrame, CURRENT_KERNEL_RELOAD_WINDOW, analyze_bugcheck,
    bugcheck_fault_ip, bugcheck_site, current_bugcheck, looks_like_kernel_pointer,
    plausible_bugcheck_code,
};
pub use crate::trapframe::KtrapFrame;

use super::disasm::{format_rflags, print_event_children, wrap_prose};

fn print_unresolved_bugcheck_data(failure: &CurrentBugcheckFailure) {
    fn slots_line(label: &str, data: &[u64; BUGCHECK_DATA_SLOTS]) -> String {
        format!(
            "{} [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
            ui::muted(label),
            data[0],
            data[1],
            data[2],
            data[3],
            data[4]
        )
    }

    outln!(
        "{} unable to resolve nt!KiBugCheckData at {:#x}: {}",
        ui::badge("BUGCHECK"),
        failure.address,
        failure.reason
    );
    let mut children: Vec<String> = Vec::new();
    if let Some(data) = &failure.slots {
        children.push(slots_line("raw slots", data));
    }
    if let Some(data) = &failure.dereferenced_slots {
        children.push(slots_line("dereferenced slots", data));
    }
    print_event_children(" ", &children);
}

/// Tree child with a dim wrapped prose tail. `hang` is the child-relative
/// indent of continuation lines; `col` the absolute column where the prose
/// starts on screen, from which the wrap width is derived.
fn wrapped_dim_tail(prefix: String, hang: usize, prose: &str, col: usize) -> String {
    let lines = wrap_prose(prose, col);
    let mut out = format!("{prefix}{}", ui::muted(&lines[0]));
    for line in &lines[1..] {
        out.push_str(&format!("\n{}{}", " ".repeat(hang), ui::muted(line)));
    }
    out
}

pub fn format_arg_value(value: u64) -> String {
    ui::addr(value)
}

/// Render a [`BugcheckInfo`] using the shared core analysis
/// ([`analyze_bugcheck`]), so the REPL and the SDK/MCP never disagree on the
/// name/arguments/responsible driver of a bugcheck.
pub fn print_bugcheck_info(debugger: &Target, info: &BugcheckInfo) {
    print_bugcheck_analysis(&analyze_bugcheck(debugger, info));
}

fn format_bugcheck_fault(fault: &BugcheckFault) -> String {
    let address = ui::addr(fault.ip);
    if fault.symbol.starts_with("0x") {
        address
    } else {
        format!("{address}  {}", ui::symbol(&fault.symbol))
    }
}

/// Render a [`BugcheckAnalysis`]: ` BUGCHECK ` badge banner with the details
/// as tree children and the args nested one level deeper; trap frames follow
/// as ordinary panes. No bold on the plate: its `\x1b[0m` reset would cut
/// the background. Callers own surrounding blank lines.
pub fn print_bugcheck_analysis(analysis: &BugcheckAnalysis) {
    outln!(
        "{}{}",
        ui::badge("BUGCHECK"),
        ui::plate(&format!(" {} ({:#010x}) ", analysis.name, analysis.code))
    );

    let mut children: Vec<String> = Vec::new();
    if let Some(driver) = &analysis.driver {
        children.push(format!("{} {}", ui::muted("module"), driver.bright_blue()));
    }
    if let Some(fault) = &analysis.fault {
        children.push(format!(
            "{} {}",
            ui::muted("fault "),
            format_bugcheck_fault(fault)
        ));
    }
    if let Some(description) = &analysis.description {
        // prose starts at column 11: tree indent (1) + gutter (3) + "reason " (7)
        children.push(wrapped_dim_tail(
            format!("{} ", ui::muted("reason")),
            7,
            description,
            11,
        ));
    }
    if let Some(source) = &analysis.source {
        children.push(format!("{} {}", ui::muted("source"), ui::muted(source)));
    }
    children.push(ui::muted("args"));
    print_event_children(" ", &children);
    let args: Vec<String> = analysis
        .args
        .iter()
        .enumerate()
        .map(|(idx, arg)| {
            // `#N` matches the stack-frame index style; the parent node
            // already says `args`.
            let prefix = format!(
                "{} {}",
                ui::muted(&format!("#{}", idx + 1)),
                format_arg_value(arg.value)
            );
            if arg.description.is_empty() {
                prefix
            } else {
                // prose at column 28: indent (4) + gutter (3) + "#N " (3)
                // + value (16) + separator (2)
                wrapped_dim_tail(format!("{prefix}  "), 21, &arg.description, 28)
            }
        })
        .collect();
    print_event_children("    ", &args);

    for trap_frame in &analysis.trap_frames {
        outln!();
        print_bugcheck_trap_frame(trap_frame);
    }
}

/// Render a trap frame named by a bugcheck parameter: always the address,
/// plus either the decoded contents or the precise decode failure.
pub fn print_bugcheck_trap_frame(trap_frame: &BugcheckTrapFrame) {
    match &trap_frame.frame {
        Some(frame) => print_ktrap_frame(frame, trap_frame.rip_symbol.as_deref()),
        None => outln!(
            "{} @ {} (unable to decode: {})",
            "trap frame".bold(),
            ui::addr(trap_frame.address),
            trap_frame.error.as_deref().unwrap_or("unknown error")
        ),
    }
}

/// Render a decoded [`KtrapFrame`] in the register-grid house style
/// ([`super::disasm::print_registers`]). r12-r15 are absent by design: the
/// kernel saves them in the exception frame, not the trap frame.
pub fn print_ktrap_frame(frame: &KtrapFrame, rip_symbol: Option<&str>) {
    outln!("{} @ {}", "trap frame".bold(), ui::addr(frame.address));
    outln!(
        "  rax {}   rbx {}   rcx {}",
        ui::addr(frame.rax),
        ui::addr(frame.rbx),
        ui::addr(frame.rcx)
    );
    outln!(
        "  rdx {}   rsi {}   rdi {}",
        ui::addr(frame.rdx),
        ui::addr(frame.rsi),
        ui::addr(frame.rdi)
    );
    outln!(
        "  rsp {}   rbp {}   rip {}",
        ui::addr(frame.rsp),
        ui::addr(frame.rbp),
        ui::addr(frame.rip)
    );
    outln!(
        "  r8  {}   r9  {}   r10 {}",
        ui::addr(frame.r8),
        ui::addr(frame.r9),
        ui::addr(frame.r10)
    );
    outln!(
        "  r11 {}   rfl {}{}",
        ui::addr(frame.r11),
        ui::addr(frame.eflags as u64),
        format_rflags(frame.eflags as u64)
    );
    outln!(
        "  cs  {:04x}  ss  {:04x}  error code {:#x}  irql {}  previous mode {}",
        frame.cs,
        frame.ss,
        frame.error_code,
        frame.previous_irql,
        if frame.previous_mode == 0 {
            "kernel"
        } else {
            "user"
        }
    );
    if let Some(symbol) = rip_symbol {
        outln!("  rip => {}", ui::symbol(symbol));
    }
}

pub fn print_bugcheck_summary(debugger: &Target, info: Option<&BugcheckInfo>) {
    if let Some(info) = info {
        print_bugcheck_info(debugger, info);
        return;
    }

    // KD normally sends the bugcheck code and parameters as debug I/O before
    // the stop packet. If that stream is missing, the same values can be read
    // from nt!KiBugCheckData while the guest is frozen mid-bugcheck.
    print_bugcheck_summary_from_memory(debugger);
}

/// Read and display `nt!KiBugCheckData` (BugCheckCode + 4 parameters) through
/// the live guest-memory view while the VM is frozen mid-bugcheck.
pub fn print_bugcheck_summary_from_memory(debugger: &Target) {
    match resolve_current_bugcheck(debugger) {
        CurrentBugcheckResolution::Resolved(analysis) => print_bugcheck_analysis(&analysis),
        CurrentBugcheckResolution::SymbolUnavailable => outln!(
            "{} guest is bugchecking (symbol nt!KiBugCheckData unavailable)",
            ui::badge("BUGCHECK")
        ),
        CurrentBugcheckResolution::Unresolved(failure) => {
            print_unresolved_bugcheck_data(&failure);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_resolved_bugcheck_fault_site() {
        let line = format_bugcheck_fault(&BugcheckFault {
            ip: 0xffff_f805_f339_1730,
            symbol: "myfault+0x1730".to_string(),
            driver: Some("myfault.sys".to_string()),
        });

        assert!(line.contains("fffff805f3391730"));
        assert!(line.contains("myfault"));
        assert!(line.contains("+0x1730"));
    }

    #[test]
    fn raw_bugcheck_fault_site_is_not_repeated() {
        let line = format_bugcheck_fault(&BugcheckFault {
            ip: 0xffff_f805_f339_1730,
            symbol: "0xfffff805f3391730".to_string(),
            driver: None,
        });

        assert_eq!(line.matches("fffff805f3391730").count(), 1);
    }
}
